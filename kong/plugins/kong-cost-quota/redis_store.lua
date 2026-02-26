-- Redis 정책/사용량 저장소 모듈.
-- 13.4 단계에서 정책 키 조회와 month/day 카운터 누적을 담당한다.
local M = {}
local policy_cache = require("kong.plugins.kong-cost-quota.policy_cache")

local WINDOWS = { "month", "day" }
local SCRIPT_KEY_COUNT = 2

-- month/day 카운터를 한 번에 처리하는 원자 차감 스크립트다.
-- 반환 형식:
-- { decision, reason, month_before, day_before, current_usage_before, projected_usage, month_after, day_after, exceeded_by }
local ATOMIC_CHARGE_LUA = [[
local month_key = KEYS[1]
local day_key = KEYS[2]

local units = tonumber(ARGV[1]) or 0
local budget_arg = ARGV[2]
local month_ttl = tonumber(ARGV[3]) or 1
local day_ttl = tonumber(ARGV[4]) or 1

if units < 0 then
  return { "error", "units_must_be_non_negative", 0, 0, 0, 0, 0, 0, 0 }
end

local month_before = tonumber(redis.call("GET", month_key) or "0")
local day_before = tonumber(redis.call("GET", day_key) or "0")

local current_usage_before = month_before
if day_before > current_usage_before then
  current_usage_before = day_before
end

local projected_month = month_before + units
local projected_day = day_before + units
local projected_usage = projected_month
if projected_day > projected_usage then
  projected_usage = projected_day
end

if budget_arg ~= nil and budget_arg ~= "" then
  local budget = tonumber(budget_arg)
  if budget == nil then
    return { "error", "budget_must_be_numeric", month_before, day_before, current_usage_before, projected_usage, month_before, day_before, 0 }
  end

  if projected_month > budget or projected_day > budget then
    return { "deny", "budget_exceeded", month_before, day_before, current_usage_before, projected_usage, month_before, day_before, projected_usage - budget }
  end
end

local month_after = tonumber(redis.call("INCRBY", month_key, units))
local day_after = tonumber(redis.call("INCRBY", day_key, units))

local month_ttl_now = tonumber(redis.call("TTL", month_key) or "-1")
if month_ttl_now < 0 then
  redis.call("EXPIRE", month_key, month_ttl)
end

local day_ttl_now = tonumber(redis.call("TTL", day_key) or "-1")
if day_ttl_now < 0 then
  redis.call("EXPIRE", day_key, day_ttl)
end

local reason = "within_budget"
if budget_arg == nil or budget_arg == "" then
  reason = "budget_missing"
end

return { "allow", reason, month_before, day_before, current_usage_before, projected_usage, month_after, day_after, 0 }
]]

local has_cjson_safe, cjson_safe = pcall(require, "cjson.safe")
local has_cjson, cjson = pcall(require, "cjson")

local function is_non_empty_string(value)
  return type(value) == "string" and value:match("%S") ~= nil
end

local function to_positive_integer(value, fallback)
  local parsed = tonumber(value)
  if not parsed then
    return fallback
  end

  parsed = math.floor(parsed)
  if parsed < 0 then
    return fallback
  end

  return parsed
end

local function is_leap_year(year)
  if year % 400 == 0 then
    return true
  end
  if year % 100 == 0 then
    return false
  end
  return year % 4 == 0
end

local function days_in_month(year, month)
  local lookup = {
    [1] = 31, [2] = 28, [3] = 31, [4] = 30, [5] = 31, [6] = 30,
    [7] = 31, [8] = 31, [9] = 30, [10] = 31, [11] = 30, [12] = 31,
  }

  if month == 2 and is_leap_year(year) then
    return 29
  end

  return lookup[month] or 30
end

local function decode_json(raw)
  local decoder = nil
  if has_cjson_safe and cjson_safe and cjson_safe.decode then
    decoder = cjson_safe.decode
  elseif has_cjson and cjson and cjson.decode then
    decoder = cjson.decode
  end

  if not decoder then
    decoder = nil
  else
    local ok, decoded = pcall(decoder, raw)
    if ok and type(decoded) == "table" then
      return decoded, nil
    end
  end

  -- 테스트/로컬 실행 환경에서 cjson이 없을 수 있어 최소 JSON 파서를 제공한다.
  local position = 1
  local text = tostring(raw or "")
  local text_length = #text

  local function skip_whitespace()
    while position <= text_length do
      local ch = text:sub(position, position)
      if ch ~= " " and ch ~= "\n" and ch ~= "\t" and ch ~= "\r" then
        break
      end
      position = position + 1
    end
  end

  local parse_value

  local function parse_string()
    if text:sub(position, position) ~= "\"" then
      return nil, "expected string"
    end
    position = position + 1

    local chars = {}
    while position <= text_length do
      local ch = text:sub(position, position)
      if ch == "\"" then
        position = position + 1
        return table.concat(chars), nil
      end

      if ch == "\\" then
        local next_ch = text:sub(position + 1, position + 1)
        local escape_map = {
          ["\""] = "\"",
          ["\\"] = "\\",
          ["/"] = "/",
          b = "\b",
          f = "\f",
          n = "\n",
          r = "\r",
          t = "\t",
        }

        if next_ch == "u" then
          return nil, "unicode escape is not supported"
        end

        local escaped = escape_map[next_ch]
        if not escaped then
          return nil, "invalid escape sequence"
        end

        chars[#chars + 1] = escaped
        position = position + 2
      else
        chars[#chars + 1] = ch
        position = position + 1
      end
    end

    return nil, "unterminated string"
  end

  local function parse_number()
    local start_pos = position
    local num_pattern = "^-?%d+%.?%d*[eE]?[+-]?%d*"
    local matched = text:sub(position):match(num_pattern)
    if not matched or matched == "" then
      return nil, "invalid number"
    end

    position = position + #matched
    local parsed = tonumber(matched)
    if not parsed then
      return nil, "invalid number"
    end

    return parsed, nil
  end

  local function parse_literal(literal, value)
    if text:sub(position, position + #literal - 1) == literal then
      position = position + #literal
      return value, nil
    end
    return nil, "invalid literal"
  end

  local function parse_array()
    if text:sub(position, position) ~= "[" then
      return nil, "expected array"
    end

    position = position + 1
    skip_whitespace()

    local result = {}
    if text:sub(position, position) == "]" then
      position = position + 1
      return result, nil
    end

    while position <= text_length do
      local value, value_err = parse_value()
      if value_err then
        return nil, value_err
      end
      result[#result + 1] = value

      skip_whitespace()
      local ch = text:sub(position, position)
      if ch == "]" then
        position = position + 1
        return result, nil
      end

      if ch ~= "," then
        return nil, "expected comma in array"
      end

      position = position + 1
      skip_whitespace()
    end

    return nil, "unterminated array"
  end

  local function parse_object()
    if text:sub(position, position) ~= "{" then
      return nil, "expected object"
    end

    position = position + 1
    skip_whitespace()

    local result = {}
    if text:sub(position, position) == "}" then
      position = position + 1
      return result, nil
    end

    while position <= text_length do
      local key, key_err = parse_string()
      if key_err then
        return nil, key_err
      end

      skip_whitespace()
      if text:sub(position, position) ~= ":" then
        return nil, "expected colon in object"
      end
      position = position + 1
      skip_whitespace()

      local value, value_err = parse_value()
      if value_err then
        return nil, value_err
      end
      result[key] = value

      skip_whitespace()
      local ch = text:sub(position, position)
      if ch == "}" then
        position = position + 1
        return result, nil
      end

      if ch ~= "," then
        return nil, "expected comma in object"
      end

      position = position + 1
      skip_whitespace()
    end

    return nil, "unterminated object"
  end

  function parse_value()
    skip_whitespace()
    local ch = text:sub(position, position)
    if ch == "" then
      return nil, "unexpected end of json"
    end
    if ch == "{" then
      return parse_object()
    end
    if ch == "[" then
      return parse_array()
    end
    if ch == "\"" then
      return parse_string()
    end
    if ch == "t" then
      return parse_literal("true", true)
    end
    if ch == "f" then
      return parse_literal("false", false)
    end
    if ch == "n" then
      return parse_literal("null", nil)
    end
    return parse_number()
  end

  local decoded, decode_err = parse_value()
  if decode_err then
    return nil, decode_err
  end

  skip_whitespace()
  if position <= text_length then
    return nil, "unexpected trailing json payload"
  end

  if type(decoded) ~= "table" then
    return nil, "json root must be an object"
  end

  return decoded, nil
end

local function is_redis_null(value)
  if value == nil then
    return true
  end

  if ngx and ngx.null and value == ngx.null then
    return true
  end

  return false
end

local function get_env(conf)
  if conf and is_non_empty_string(conf.redis_env) then
    return conf.redis_env
  end
  return "prod"
end

local function get_grace_days(conf)
  if conf then
    return to_positive_integer(conf.usage_grace_days, 7)
  end
  return 7
end

local function get_now_epoch(conf)
  if conf and type(conf.redis_now_epoch) == "number" then
    return math.floor(conf.redis_now_epoch)
  end

  if ngx and type(ngx.time) == "function" then
    return ngx.time()
  end

  return os.time()
end

local function ensure_number(value, default_value)
  local parsed = tonumber(value)
  if not parsed then
    return default_value
  end
  return parsed
end

local function normalize_policy_version(policy)
  if type(policy) ~= "table" then
    return nil
  end

  if type(policy.version) == "string" then
    return policy.version
  end

  if type(policy.version) == "number" then
    return tostring(policy.version)
  end

  return nil
end

function M.resolve_scope_and_id(identity)
  if type(identity) ~= "table" then
    return nil, nil, "identity must be an object"
  end

  if is_non_empty_string(identity.client_id) then
    return "client", identity.client_id, nil
  end

  if is_non_empty_string(identity.org_id) then
    return "org", identity.org_id, nil
  end

  return nil, nil, "client_id or org_id is required"
end

function M.current_epoch(conf)
  return get_now_epoch(conf)
end

function M.atomic_charge_script()
  return ATOMIC_CHARGE_LUA
end

function M.build_policy_key(env, scope, id)
  return string.format("policy:%s:%s:%s", env, scope, id)
end

function M.build_usage_key(env, window, scope, id, bucket)
  return string.format("usage:%s:%s:%s:%s:%s", env, window, scope, id, bucket)
end

function M.compute_bucket(window, now_epoch)
  local utc = os.date("!*t", now_epoch)
  if window == "month" then
    return string.format("%04d-%02d", utc.year, utc.month), nil
  end

  if window == "day" then
    return string.format("%04d-%02d-%02d", utc.year, utc.month, utc.day), nil
  end

  return nil, "unsupported window: " .. tostring(window)
end

function M.compute_ttl_seconds(window, now_epoch, grace_days)
  local utc = os.date("!*t", now_epoch)
  local seconds_of_day = (utc.hour * 3600) + (utc.min * 60) + utc.sec
  local until_end = nil

  if window == "day" then
    until_end = 86400 - seconds_of_day
  elseif window == "month" then
    local month_days = days_in_month(utc.year, utc.month)
    local remaining_days = month_days - utc.day
    until_end = (remaining_days * 86400) + (86400 - seconds_of_day)
  else
    return nil, "unsupported window: " .. tostring(window)
  end

  local ttl = until_end + (to_positive_integer(grace_days, 7) * 86400)
  if ttl < 1 then
    ttl = 1
  end

  return ttl, nil
end

function M.build_usage_window_meta(conf, scope, id, now_epoch)
  local env = get_env(conf)
  local base_epoch = now_epoch or get_now_epoch(conf)
  local grace_days = get_grace_days(conf)

  local meta = {
    keys = {},
    buckets = {},
    ttl_seconds = {},
  }

  for _, window in ipairs(WINDOWS) do
    local bucket, bucket_err = M.compute_bucket(window, base_epoch)
    if bucket_err then
      return nil, bucket_err
    end

    local ttl_seconds, ttl_err = M.compute_ttl_seconds(window, base_epoch, grace_days)
    if ttl_err then
      return nil, ttl_err
    end

    meta.keys[window] = M.build_usage_key(env, window, scope, id, bucket)
    meta.buckets[window] = bucket
    meta.ttl_seconds[window] = ttl_seconds
  end

  return meta, nil
end

function M.open_client(conf)
  if conf and type(conf.redis_client_factory) == "function" then
    local client, err = conf.redis_client_factory(conf)
    if not client then
      return nil, "failed to build redis client: " .. tostring(err), true
    end
    return client, nil, true
  end

  if not (conf and is_non_empty_string(conf.redis_host)) then
    return nil, "redis host is not configured", false
  end

  local ok, redis_mod = pcall(require, "resty.redis")
  if not ok then
    return nil, "resty.redis is unavailable: " .. tostring(redis_mod), false
  end

  local client = redis_mod:new()
  if not client then
    return nil, "failed to create redis client", false
  end

  local timeout = ensure_number(conf.redis_timeout_ms, 20)
  if type(client.set_timeout) == "function" then
    client:set_timeout(timeout)
  end

  local connected, connect_err = client:connect(conf.redis_host, ensure_number(conf.redis_port, 6379))
  if not connected then
    return nil, "failed to connect redis: " .. tostring(connect_err), false
  end

  if is_non_empty_string(conf.redis_password) then
    local auth_ok, auth_err = client:auth(conf.redis_password)
    if not auth_ok then
      return nil, "failed to auth redis: " .. tostring(auth_err), false
    end
  end

  local db_index = ensure_number(conf.redis_database, 0)
  if db_index > 0 then
    local selected, select_err = client:select(db_index)
    if not selected then
      return nil, "failed to select redis db: " .. tostring(select_err), false
    end
  end

  return client, nil, false
end

function M.close_client(client, is_factory_client)
  if not client then
    return
  end

  if is_factory_client then
    if type(client.close) == "function" then
      pcall(client.close, client)
    end
    return
  end

  if type(client.set_keepalive) == "function" then
    pcall(client.set_keepalive, client, 60000, 100)
    return
  end

  if type(client.close) == "function" then
    pcall(client.close, client)
  end
end

local function build_policy_candidates(conf, identity)
  local scope, id, scope_err = M.resolve_scope_and_id(identity)
  if scope_err then
    return nil, scope_err
  end

  local env = get_env(conf)
  local candidates = {
    {
      scope = scope,
      id = id,
      key = M.build_policy_key(env, scope, id),
    },
  }

  -- client 정책이 없으면 org 정책으로 폴백한다.
  if scope == "client" and is_non_empty_string(identity.org_id) then
    candidates[#candidates + 1] = {
      scope = "org",
      id = identity.org_id,
      key = M.build_policy_key(env, "org", identity.org_id),
    }
  end

  return candidates, nil
end

local function fetch_policy_from_key(client, key, scope, id)
  local raw_value, get_err = client:get(key)
  if get_err then
    return nil, nil, "failed to fetch policy: " .. tostring(get_err), false
  end

  if is_redis_null(raw_value) then
    return nil, nil, nil, true
  end

  local decoded, decode_err = decode_json(raw_value)
  if decode_err then
    return nil, nil, "failed to decode policy json: " .. tostring(decode_err), false
  end

  local version = normalize_policy_version(decoded)
  return decoded, {
    policy_key = key,
    policy_source = "redis",
    policy_scope = scope,
    policy_id = id,
    policy_version = version,
    raw_policy = raw_value,
    cache_hit = false,
  }, nil, false
end

function M.fetch_policy(client, conf, identity)
  if not client then
    return nil, nil, "redis client is required"
  end

  local candidates, candidates_err = build_policy_candidates(conf, identity)
  if candidates_err then
    return nil, nil, candidates_err
  end

  for _, candidate in ipairs(candidates) do
    local policy, meta, fetch_err, not_found = fetch_policy_from_key(client, candidate.key, candidate.scope, candidate.id)
    if fetch_err then
      return nil, nil, fetch_err
    end

    if not not_found then
      return policy, meta, nil
    end
  end

  local primary = candidates[1]
  return nil, {
    policy_source = "redis",
    policy_scope = primary and primary.scope or nil,
    policy_id = primary and primary.id or nil,
    cache_hit = false,
  }, nil
end

function M.fetch_policy_with_cache(client, conf, identity)
  if not client then
    return nil, nil, "redis client is required"
  end

  local candidates, candidates_err = build_policy_candidates(conf, identity)
  if candidates_err then
    return nil, nil, candidates_err
  end

  local cache_enabled = policy_cache.cache_enabled(conf)

  for _, candidate in ipairs(candidates) do
    if cache_enabled then
      local cached_entry, cache_source = policy_cache.get_policy(conf, candidate.key)
      if cached_entry and is_non_empty_string(cached_entry.raw_policy) then
        local cached_policy, decode_err = decode_json(cached_entry.raw_policy)
        if decode_err then
          policy_cache.invalidate_policy(conf, candidate.key)
        else
          local cached_version = cached_entry.policy_version or normalize_policy_version(cached_policy)
          local should_probe = policy_cache.should_probe_version(conf, candidate.key)
          if should_probe then
            local fresh_policy, fresh_meta, fresh_err, not_found = fetch_policy_from_key(
              client,
              candidate.key,
              candidate.scope,
              candidate.id
            )

            if fresh_err then
              -- Redis 조회 실패 시 기존 캐시를 우선 사용해 fail-open 성격을 유지한다.
              policy_cache.mark_probed(conf, candidate.key)
              return cached_policy, {
                policy_key = candidate.key,
                policy_source = cache_source,
                policy_scope = candidate.scope,
                policy_id = candidate.id,
                policy_version = cached_version,
                cache_hit = true,
                redis_error = fresh_err,
              }, nil
            end

            if not not_found and fresh_policy then
              local fresh_version = fresh_meta.policy_version
              if fresh_version ~= cached_version then
                policy_cache.set_policy(conf, candidate.key, {
                  raw_policy = fresh_meta.raw_policy,
                  policy_version = fresh_version,
                })
                policy_cache.mark_probed(conf, candidate.key)
                return fresh_policy, fresh_meta, nil
              end
            elseif not_found then
              policy_cache.invalidate_policy(conf, candidate.key)
              -- 현재 후보가 삭제된 경우 다음 후보(org)를 탐색한다.
              goto continue_candidate
            end

            policy_cache.mark_probed(conf, candidate.key)
          end

          return cached_policy, {
            policy_key = candidate.key,
            policy_source = cache_source,
            policy_scope = candidate.scope,
            policy_id = candidate.id,
            policy_version = cached_version,
            cache_hit = true,
          }, nil
        end
      end
    end

    do
      local policy, meta, fetch_err, not_found = fetch_policy_from_key(client, candidate.key, candidate.scope, candidate.id)
      if fetch_err then
        return nil, nil, fetch_err
      end

      if not not_found and policy then
        if cache_enabled then
          policy_cache.set_policy(conf, candidate.key, {
            raw_policy = meta.raw_policy,
            policy_version = meta.policy_version,
          })
          policy_cache.mark_probed(conf, candidate.key)
        end
        return policy, meta, nil
      end
    end

    ::continue_candidate::
  end

  local primary = candidates[1]
  return nil, {
    policy_source = "redis_miss",
    policy_scope = primary and primary.scope or nil,
    policy_id = primary and primary.id or nil,
    cache_hit = false,
  }, nil
end

function M.read_usages(client, conf, scope, id, now_epoch)
  if not client then
    return nil, nil, "redis client is required"
  end

  local meta, meta_err = M.build_usage_window_meta(conf, scope, id, now_epoch)
  if meta_err then
    return nil, nil, meta_err
  end

  local usages = {}
  for _, window in ipairs(WINDOWS) do
    local key = meta.keys[window]
    local raw_usage, get_err = client:get(key)
    if get_err then
      return nil, nil, "failed to read usage: " .. tostring(get_err)
    end

    local usage_value = 0
    if not is_redis_null(raw_usage) then
      usage_value = tonumber(raw_usage)
      if not usage_value then
        return nil, nil, "usage value must be numeric for key: " .. key
      end
    end

    usages[window] = usage_value
  end

  return usages, meta, nil
end

local function parse_atomic_result(raw_result)
  if type(raw_result) ~= "table" then
    return nil, "atomic script result must be an array"
  end

  local decision_value = raw_result[1]
  local reason_value = raw_result[2]
  if decision_value == "error" then
    return nil, tostring(reason_value or "unknown_script_error")
  end

  if decision_value ~= "allow" and decision_value ~= "deny" then
    return nil, "invalid decision from atomic script: " .. tostring(decision_value)
  end

  local parsed = {
    decision = decision_value,
    reason = tostring(reason_value or "unknown"),
    month_before = tonumber(raw_result[3]) or 0,
    day_before = tonumber(raw_result[4]) or 0,
    current_usage_before = tonumber(raw_result[5]) or 0,
    projected_usage = tonumber(raw_result[6]) or 0,
    month_after = tonumber(raw_result[7]) or 0,
    day_after = tonumber(raw_result[8]) or 0,
    exceeded_by = tonumber(raw_result[9]) or 0,
  }

  return parsed, nil
end

local function load_script_sha(client, script)
  if type(client.script) == "function" then
    return client:script("load", script)
  end

  if type(client.script_load) == "function" then
    return client:script_load(script)
  end

  return nil, "script load is not supported by redis client"
end

local function call_evalsha(client, script_sha, keys, args)
  if type(client.evalsha) ~= "function" then
    return nil, "evalsha_not_supported"
  end

  return client:evalsha(
    script_sha,
    SCRIPT_KEY_COUNT,
    keys.month,
    keys.day,
    args.units,
    args.budget,
    args.month_ttl,
    args.day_ttl
  )
end

local function call_eval(client, script, keys, args)
  if type(client.eval) ~= "function" then
    return nil, "eval_not_supported"
  end

  return client:eval(
    script,
    SCRIPT_KEY_COUNT,
    keys.month,
    keys.day,
    args.units,
    args.budget,
    args.month_ttl,
    args.day_ttl
  )
end

function M.atomic_charge_usages(client, conf, scope, id, units, budget, now_epoch)
  if not client then
    return nil, nil, "redis client is required"
  end

  local charge_units = tonumber(units)
  if not charge_units or charge_units < 0 then
    return nil, nil, "units must be >= 0"
  end

  local meta, meta_err = M.build_usage_window_meta(conf, scope, id, now_epoch)
  if meta_err then
    return nil, nil, meta_err
  end

  local budget_value = budget
  if budget_value ~= nil then
    budget_value = tonumber(budget_value)
    if not budget_value or budget_value < 0 then
      return nil, nil, "budget must be >= 0"
    end
  end

  local args = {
    units = tostring(math.floor(charge_units)),
    budget = budget_value == nil and "" or tostring(budget_value),
    month_ttl = tostring(math.floor(meta.ttl_seconds.month)),
    day_ttl = tostring(math.floor(meta.ttl_seconds.day)),
  }

  local script = ATOMIC_CHARGE_LUA
  local script_sha = conf and conf.__atomic_charge_sha or nil
  local raw_result = nil
  local exec_err = nil

  if is_non_empty_string(script_sha) then
    raw_result, exec_err = call_evalsha(client, script_sha, meta.keys, args)
  end

  local should_load_script = false
  if not raw_result and exec_err then
    local err_text = tostring(exec_err)
    if err_text:find("NOSCRIPT", 1, true) or err_text == "evalsha_not_supported" then
      should_load_script = true
    else
      return nil, nil, "failed to execute evalsha: " .. err_text
    end
  elseif not raw_result and not exec_err then
    should_load_script = true
  end

  if should_load_script then
    local loaded_sha, load_err = load_script_sha(client, script)
    if loaded_sha and conf then
      conf.__atomic_charge_sha = tostring(loaded_sha)
      script_sha = conf.__atomic_charge_sha
      raw_result, exec_err = call_evalsha(client, script_sha, meta.keys, args)
    end

    if (not raw_result) and exec_err and tostring(exec_err):find("NOSCRIPT", 1, true) then
      -- 드물게 로드 직후 NOSCRIPT가 발생하면 EVAL로 즉시 폴백한다.
      raw_result, exec_err = call_eval(client, script, meta.keys, args)
    elseif (not raw_result) and load_err then
      raw_result, exec_err = call_eval(client, script, meta.keys, args)
      if not raw_result and exec_err then
        return nil, nil, "failed to execute eval after script load error: " .. tostring(exec_err)
      end
    elseif (not raw_result) and exec_err and tostring(exec_err) == "evalsha_not_supported" then
      raw_result, exec_err = call_eval(client, script, meta.keys, args)
    elseif (not raw_result) and exec_err then
      return nil, nil, "failed to execute evalsha after script load: " .. tostring(exec_err)
    end
  end

  if not raw_result then
    raw_result, exec_err = call_eval(client, script, meta.keys, args)
    if exec_err then
      return nil, nil, "failed to execute atomic charge script: " .. tostring(exec_err)
    end
  end

  local parsed, parse_err = parse_atomic_result(raw_result)
  if parse_err then
    return nil, nil, "failed to parse atomic script result: " .. tostring(parse_err)
  end

  return parsed, {
    keys = meta.keys,
    buckets = meta.buckets,
    ttl_seconds = meta.ttl_seconds,
    script_sha = is_non_empty_string(script_sha) and script_sha or (conf and conf.__atomic_charge_sha) or nil,
  }, nil
end

function M.increment_usages(client, conf, scope, id, units, now_epoch)
  if not client then
    return nil, nil, "redis client is required"
  end

  local charge_units = tonumber(units)
  if not charge_units or charge_units < 0 then
    return nil, nil, "units must be >= 0"
  end

  local base_epoch = now_epoch
  if type(base_epoch) ~= "number" then
    base_epoch = get_now_epoch(conf)
  end

  local usages, meta, read_err = M.read_usages(client, conf, scope, id, base_epoch)
  if read_err then
    return nil, nil, read_err
  end

  local updated = {}
  for _, window in ipairs(WINDOWS) do
    local key = meta.keys[window]
    local ttl_seconds = meta.ttl_seconds[window]

    local after_incr, incr_err = client:incrby(key, charge_units)
    if incr_err then
      return nil, nil, "failed to increase usage: " .. tostring(incr_err)
    end

    local normalized_usage = tonumber(after_incr)
    if not normalized_usage then
      return nil, nil, "incrby result must be numeric for key: " .. key
    end

    local current_ttl, ttl_err = client:ttl(key)
    if ttl_err then
      return nil, nil, "failed to read ttl: " .. tostring(ttl_err)
    end

    local ttl_value = tonumber(current_ttl)
    if not ttl_value then
      return nil, nil, "ttl result must be numeric for key: " .. key
    end

    if ttl_value < 0 then
      local expire_ok, expire_err = client:expire(key, ttl_seconds)
      if expire_err then
        return nil, nil, "failed to set ttl: " .. tostring(expire_err)
      end

      local expire_result = tonumber(expire_ok) or 0
      if expire_result < 1 then
        return nil, nil, "expire command failed for key: " .. key
      end
    end

    updated[window] = normalized_usage
  end

  return updated, {
    keys = meta.keys,
    buckets = meta.buckets,
    ttl_seconds = meta.ttl_seconds,
    before = usages,
  }, nil
end

return M
