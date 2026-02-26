-- Redis 장애 전략과 서킷브레이커를 관리하는 모듈.
-- 13.7 단계 요구사항(장애 분기/실패율 기반 회로 차단)을 담당한다.
local M = {}

local FALLBACK_STORE = {}

local function is_non_empty_string(value)
  return type(value) == "string" and value:match("%S") ~= nil
end

local function now_epoch(conf)
  if type(conf) == "table" and type(conf.redis_now_epoch) == "number" then
    return tonumber(conf.redis_now_epoch)
  end

  if ngx and type(ngx.now) == "function" then
    return ngx.now()
  end

  return os.time()
end

local function to_integer(value, default_value)
  local parsed = tonumber(value)
  if not parsed then
    return default_value
  end
  return math.floor(parsed)
end

local function to_number(value, default_value)
  local parsed = tonumber(value)
  if not parsed then
    return default_value
  end
  return parsed
end

local function get_shared_dict(conf)
  local dict_name = type(conf) == "table" and conf.redis_circuit_shm or nil
  if not is_non_empty_string(dict_name) then
    dict_name = "kong_cost_quota_circuit"
  end

  if not (ngx and type(ngx.shared) == "table") then
    return nil
  end

  return ngx.shared[dict_name]
end

local function fallback_get(key, now_ts)
  local item = FALLBACK_STORE[key]
  if not item then
    return nil
  end

  if item.expires_at and item.expires_at <= now_ts then
    FALLBACK_STORE[key] = nil
    return nil
  end

  return item.value
end

local function fallback_set(key, value, ttl, now_ts)
  local expires_at = nil
  if ttl and ttl > 0 then
    expires_at = now_ts + ttl
  end

  FALLBACK_STORE[key] = {
    value = value,
    expires_at = expires_at,
  }
end

local function store_get(conf, key)
  local dict = get_shared_dict(conf)
  if dict then
    return dict:get(key)
  end
  return fallback_get(key, now_epoch(conf))
end

local function store_set(conf, key, value, ttl)
  local dict = get_shared_dict(conf)
  if dict then
    dict:set(key, value, ttl)
    return
  end
  fallback_set(key, value, ttl, now_epoch(conf))
end

local function store_incr(conf, key, amount, ttl)
  local dict = get_shared_dict(conf)
  if dict and type(dict.incr) == "function" then
    local value, incr_err = dict:incr(key, amount)
    if not value and incr_err == "not found" then
      dict:set(key, amount, ttl)
      return amount
    end
    if value then
      return tonumber(value) or 0
    end
  elseif dict then
    local current = tonumber(dict:get(key)) or 0
    local next_value = current + amount
    dict:set(key, next_value, ttl)
    return next_value
  end

  local now_ts = now_epoch(conf)
  local current = tonumber(fallback_get(key, now_ts)) or 0
  local next_value = current + amount
  fallback_set(key, next_value, ttl, now_ts)
  return next_value
end

local function resolve_window_sec(conf)
  local window_sec = to_integer(type(conf) == "table" and conf.circuit_failure_window_sec or nil, 30)
  if window_sec < 5 then
    window_sec = 5
  end
  if window_sec > 300 then
    window_sec = 300
  end
  return window_sec
end

local function resolve_min_requests(conf)
  local min_requests = to_integer(type(conf) == "table" and conf.circuit_min_requests or nil, 20)
  if min_requests < 1 then
    min_requests = 1
  end
  if min_requests > 100000 then
    min_requests = 100000
  end
  return min_requests
end

local function resolve_threshold(conf)
  local threshold = to_number(type(conf) == "table" and conf.circuit_failure_threshold or nil, 0.5)
  if threshold < 0 then
    threshold = 0
  end
  if threshold > 1 then
    threshold = 1
  end
  return threshold
end

local function resolve_open_sec(conf)
  local open_sec = to_integer(type(conf) == "table" and conf.circuit_open_sec or nil, 15)
  if open_sec < 1 then
    open_sec = 1
  end
  if open_sec > 300 then
    open_sec = 300
  end
  return open_sec
end

local function key_prefix(conf)
  local env = type(conf) == "table" and conf.redis_env or nil
  if not is_non_empty_string(env) then
    env = "prod"
  end
  return "cost_quota:cb:" .. env
end

local function current_bucket(conf)
  local window_sec = resolve_window_sec(conf)
  local now_ts = now_epoch(conf)
  return math.floor(now_ts / window_sec), window_sec, now_ts
end

function M.circuit_enabled(conf)
  if type(conf) ~= "table" then
    return true
  end
  return conf.circuit_breaker_enabled ~= false
end

function M.resolve_failure_strategy(conf)
  local strategy = type(conf) == "table" and conf.failure_strategy or nil
  if strategy == "fail_closed" then
    return "fail_closed"
  end
  return "fail_open"
end

function M.resolve_failure_deny_status(conf)
  local status = to_integer(type(conf) == "table" and conf.failure_deny_status or nil, 503)
  if status == 429 then
    return 429
  end
  return 503
end

function M.is_circuit_open(conf)
  if not M.circuit_enabled(conf) then
    return false, nil
  end

  local now_ts = now_epoch(conf)
  local open_until = tonumber(store_get(conf, key_prefix(conf) .. ":open_until")) or 0
  if open_until > now_ts then
    return true, {
      open_until = open_until,
      now = now_ts,
      source = "redis_circuit_open",
    }
  end

  return false, nil
end

function M.record_redis_result(conf, is_success)
  if not M.circuit_enabled(conf) then
    return {
      circuit_opened = false,
      total = 0,
      failures = 0,
      failure_rate = 0,
    }
  end

  local bucket, window_sec, now_ts = current_bucket(conf)
  local ttl = window_sec * 2
  local prefix = key_prefix(conf)

  local total_key = string.format("%s:total:%d", prefix, bucket)
  local fail_key = string.format("%s:fail:%d", prefix, bucket)

  local total = store_incr(conf, total_key, 1, ttl)
  local failures = tonumber(store_get(conf, fail_key)) or 0
  if is_success ~= true then
    failures = store_incr(conf, fail_key, 1, ttl)
  end

  local rate = 0
  if total > 0 then
    rate = failures / total
  end

  local min_requests = resolve_min_requests(conf)
  local threshold = resolve_threshold(conf)
  local opened = false

  if total >= min_requests and rate >= threshold then
    local open_until = now_ts + resolve_open_sec(conf)
    store_set(conf, prefix .. ":open_until", open_until, resolve_open_sec(conf))
    opened = true
  end

  return {
    circuit_opened = opened,
    total = total,
    failures = failures,
    failure_rate = rate,
  }
end

function M._reset_for_test()
  FALLBACK_STORE = {}
end

return M
