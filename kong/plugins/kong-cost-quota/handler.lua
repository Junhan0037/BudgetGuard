local policy_model = require("kong.plugins.kong-cost-quota.policy_model")
local route_matcher = require("kong.plugins.kong-cost-quota.route_matcher")
local unit_calculator = require("kong.plugins.kong-cost-quota.unit_calculator")
local decision = require("kong.plugins.kong-cost-quota.decision")
local redis_store = require("kong.plugins.kong-cost-quota.redis_store")
local failure_control = require("kong.plugins.kong-cost-quota.failure_control")

-- JSON 직렬화는 런타임 환경에 따라 cjson.safe 또는 cjson을 사용한다.
local has_cjson_safe, cjson_safe = pcall(require, "cjson.safe")
local has_cjson, cjson = pcall(require, "cjson")

local plugin = {
  PRIORITY = 1000,
  VERSION = "0.1.0",
}

local IDENTITY_FIELDS = { "org_id", "client_id", "plan" }

local function is_non_empty_string(value)
  return type(value) == "string" and value:match("%S") ~= nil
end

local function get_header(name)
  if not (kong and kong.request and kong.request.get_header) then
    return nil
  end
  return kong.request.get_header(name)
end

local function get_route_id()
  if not (kong and kong.router and kong.router.get_route) then
    return nil
  end
  local route = kong.router.get_route()
  return route and route.id or nil
end

local function get_service_name()
  if not (kong and kong.router and kong.router.get_service) then
    return nil
  end
  local service = kong.router.get_service()
  return service and service.name or nil
end

local function get_path()
  if not (kong and kong.request and kong.request.get_path) then
    return ""
  end
  local path = kong.request.get_path()
  return type(path) == "string" and path or ""
end

local function get_method()
  if not (kong and kong.request and kong.request.get_method) then
    return "GET"
  end
  local method = kong.request.get_method()
  if type(method) ~= "string" or method == "" then
    return "GET"
  end
  return method
end

local function get_ctx_shared()
  if not (kong and kong.ctx and type(kong.ctx.shared) == "table") then
    return nil
  end
  return kong.ctx.shared
end

local function set_runtime_ctx(data)
  local shared = get_ctx_shared()
  if not shared then
    return
  end
  shared.cost_quota_ctx = data
end

local function normalize_policy_source(policy_source)
  -- 내부 소스 값을 PRD 표준(source=cache|redis|default)으로 정규화한다.
  if policy_source == "cache_l1" or policy_source == "cache_l2" then
    return "cache"
  end

  if policy_source == "redis" or policy_source == "redis_miss" then
    return "redis"
  end

  if policy_source == "config" or policy_source == "none" then
    return "default"
  end

  return "default"
end

local function encode_json(payload)
  local encoder = nil
  if has_cjson_safe and cjson_safe and cjson_safe.encode then
    encoder = cjson_safe.encode
  elseif has_cjson and cjson and cjson.encode then
    encoder = cjson.encode
  end

  if encoder then
    local ok, encoded = pcall(encoder, payload)
    if ok and type(encoded) == "string" then
      return encoded
    end
  end

  -- 최소 보장을 위한 폴백 직렬화다.
  local segments = {}
  for key, value in pairs(payload or {}) do
    if value ~= nil then
      segments[#segments + 1] = tostring(key) .. "=" .. tostring(value)
    end
  end
  table.sort(segments)
  return "{" .. table.concat(segments, ",") .. "}"
end

local function log_notice(message)
  if kong and kong.log and kong.log.notice then
    kong.log.notice(message)
  end
end

local function log_warn(message)
  if kong and kong.log and kong.log.warn then
    kong.log.warn(message)
    return
  end
  log_notice(message)
end

local function exit_with_status(status_code, body)
  if kong and kong.response and kong.response.exit then
    return kong.response.exit(status_code, body)
  end
  return {
    status = status_code,
    body = body,
  }
end

local function emit_failure_alarm(payload)
  -- 운영 알람 연계를 위해 장애 이벤트를 구조화 로그로 남긴다.
  log_warn("cost_quota_failure " .. encode_json(payload))
end

local function set_response_header(name, value)
  if value == nil then
    return
  end

  if not (kong and kong.response and type(kong.response.set_header) == "function") then
    return
  end

  kong.response.set_header(name, tostring(value))
end

local function resolve_retry_after_seconds(runtime_ctx)
  -- 현재 단계는 day 윈도우 TTL을 Retry-After 기준으로 사용한다.
  local ttl_seconds = runtime_ctx and runtime_ctx.ttl_seconds or nil
  if type(ttl_seconds) ~= "table" then
    return nil
  end

  local day_ttl = tonumber(ttl_seconds.day)
  if not day_ttl or day_ttl <= 0 then
    return nil
  end

  return math.floor(day_ttl)
end

local function set_observability_headers(runtime_ctx)
  if type(runtime_ctx) ~= "table" then
    return
  end

  local normalized_source = normalize_policy_source(runtime_ctx.policy_source)
  set_response_header("X-Usage-Units", runtime_ctx.units or 0)
  set_response_header("X-Remaining-Units", runtime_ctx.remaining)
  set_response_header("X-Budget-Window", "day")
  set_response_header("X-Policy-Version", runtime_ctx.policy_version)
  set_response_header("X-Policy-Source", normalized_source)

  -- 차단 응답에서만 재시도 가이드를 제공한다.
  if runtime_ctx.decision == "deny" then
    local retry_after = resolve_retry_after_seconds(runtime_ctx)
    if retry_after then
      set_response_header("Retry-After", retry_after)
    end
  end
end

local function emit_metric(name, value, tags)
  -- 메트릭 수집기는 구조화 로그(cost_quota_metric)를 파싱해 적재한다.
  log_notice("cost_quota_metric " .. encode_json({
    metric = name,
    value = value,
    result = tags and tags.result or nil,
    source = tags and tags.source or nil,
  }))
end

local function emit_observability_metrics(runtime_ctx)
  if type(runtime_ctx) ~= "table" then
    return
  end

  local request_result = runtime_ctx.decision == "deny" and "deny" or "allow"
  local request_source = normalize_policy_source(runtime_ctx.policy_source)
  local cache_hit = 0
  if runtime_ctx.policy_source == "cache_l1" or runtime_ctx.policy_source == "cache_l2" then
    cache_hit = 1
  end

  emit_metric("cost_quota.requests", 1, {
    result = request_result,
    source = request_source,
  })
  emit_metric("cost_quota.units_charged", tonumber(runtime_ctx.units) or 0)
  -- 현재 단계는 Redis 지연시간 측정 지표 골격만 제공하고 후속 단계에서 실측을 확장한다.
  emit_metric("cost_quota.redis_latency_ms", tonumber(runtime_ctx.redis_latency_ms) or 0)
  emit_metric("cost_quota.policy_cache_hit", cache_hit)
end

local function commit_runtime_ctx(runtime_ctx)
  set_runtime_ctx(runtime_ctx)
  set_observability_headers(runtime_ctx)
  emit_observability_metrics(runtime_ctx)
end

local function copy_non_empty_fields(source)
  local copied = {}
  if type(source) ~= "table" then
    return copied
  end

  for _, field in ipairs(IDENTITY_FIELDS) do
    if is_non_empty_string(source[field]) then
      copied[field] = source[field]
    end
  end

  return copied
end

-- 우선순위가 높은 source가 먼저 병합되므로 기존 값은 덮어쓰지 않는다.
local function merge_identity(target, source, source_name, source_map)
  if type(source) ~= "table" then
    return
  end

  for _, field in ipairs(IDENTITY_FIELDS) do
    if not is_non_empty_string(target[field]) and is_non_empty_string(source[field]) then
      target[field] = source[field]
      source_map[field] = source_name
    end
  end
end

local function get_claims_from_shared(shared)
  if type(shared) ~= "table" then
    return nil
  end

  local token = shared.authenticated_jwt_token
  if type(token) == "table" and type(token.claims) == "table" then
    return token.claims
  end

  if type(shared.jwt_claims) == "table" then
    return shared.jwt_claims
  end

  if type(shared.authenticated_claims) == "table" then
    return shared.authenticated_claims
  end

  return nil
end

local function extract_identity_from_jwt()
  local shared = get_ctx_shared()
  local claims = get_claims_from_shared(shared)
  return copy_non_empty_fields(claims)
end

local function extract_identity_from_mtls()
  local subject = nil
  local serial = nil

  if kong and kong.client and kong.client.tls then
    if type(kong.client.tls.get_subject_dn) == "function" then
      subject = kong.client.tls.get_subject_dn()
    end

    if type(kong.client.tls.get_serial_number) == "function" then
      serial = kong.client.tls.get_serial_number()
    end
  end

  if ngx and ngx.var then
    if not is_non_empty_string(subject) then
      subject = ngx.var.ssl_client_s_dn
    end

    if not is_non_empty_string(serial) then
      serial = ngx.var.ssl_client_serial
    end
  end

  local identity = {}
  if is_non_empty_string(serial) then
    identity.client_id = serial
  elseif is_non_empty_string(subject) then
    identity.client_id = subject
  end

  return identity
end

local function extract_identity_from_consumer()
  if not (kong and kong.client and kong.client.get_consumer) then
    return {}
  end

  local consumer = kong.client.get_consumer()
  if type(consumer) ~= "table" then
    return {}
  end

  if is_non_empty_string(consumer.id) then
    return { client_id = consumer.id }
  end

  return {}
end

local function extract_identity_from_headers(conf)
  if not (conf and conf.allow_trusted_identity_headers) then
    return {}
  end

  return {
    org_id = get_header("x-org-id"),
    client_id = get_header("x-client-id"),
    plan = get_header("x-plan"),
  }
end

local function extract_identity(conf)
  local identity = {}
  local source_map = {}

  merge_identity(identity, extract_identity_from_jwt(), "jwt_claims", source_map)
  merge_identity(identity, extract_identity_from_mtls(), "mtls", source_map)
  merge_identity(identity, extract_identity_from_consumer(), "api_key_consumer", source_map)
  merge_identity(identity, extract_identity_from_headers(conf), "trusted_header", source_map)

  return identity, source_map
end

local function resolve_budget(rule, policy)
  if type(rule) == "table" and type(rule.budget) == "number" then
    return rule.budget
  end

  if policy and type(policy.default) == "table" and type(policy.default.budget) == "number" then
    return policy.default.budget
  end

  return nil
end

local function resolve_policy_version(policy)
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

local function build_runtime_ctx(params)
  local budget = params.meta and params.meta.budget or nil
  local projected = params.meta and params.meta.projected_usage or nil
  local remaining = nil
  if type(budget) == "number" and type(projected) == "number" then
    remaining = math.max(budget - projected, 0)
  end

  return {
    identity = params.identity or {},
    identity_source = params.identity_source or {},
    units = params.units or 0,
    current_usage = params.current_usage or 0,
    decision = params.decision or "allow",
    reason = params.reason or "unknown",
    route_id = params.route_id,
    remaining = remaining,
    policy_version = params.policy_version,
    policy_source = params.policy_source,
    policy_key = params.policy_key,
    usage_scope = params.usage_scope,
    usage_id = params.usage_id,
    usage_month = params.usage_month,
    usage_day = params.usage_day,
    usage_keys = params.usage_keys or {},
    ttl_seconds = params.ttl_seconds or {},
    redis_error = params.redis_error,
    usage_error = params.usage_error,
    increment_error = params.increment_error,
    atomic = params.atomic or false,
    atomic_script_sha = params.atomic_script_sha,
    atomic_error = params.atomic_error,
    month_before = params.month_before,
    day_before = params.day_before,
    month_after = params.month_after,
    day_after = params.day_after,
    exceeded_by = params.exceeded_by,
    failure_strategy = params.failure_strategy,
    failure_source = params.failure_source,
    failure_deny_status = params.failure_deny_status,
    redis_circuit_open = params.redis_circuit_open,
  }
end

local function should_use_redis(conf)
  if type(conf) ~= "table" then
    return false
  end

  if type(conf.redis_client_factory) == "function" then
    return true
  end

  return is_non_empty_string(conf.redis_host)
end

local function close_redis_client(client, is_factory_client)
  if not client then
    return
  end
  redis_store.close_client(client, is_factory_client)
end

local function resolve_policy(conf, identity, redis_client)
  local scope, id, scope_err = redis_store.resolve_scope_and_id(identity)
  if scope_err then
    return nil, {
      policy_source = "none",
      policy_scope = nil,
      policy_id = nil,
      redis_error = scope_err,
    }
  end

  local meta = {
    policy_source = "none",
    policy_scope = scope,
    policy_id = id,
    policy_key = nil,
    redis_error = nil,
  }

  if redis_client then
    local redis_policy, redis_meta, redis_err = redis_store.fetch_policy_with_cache(redis_client, conf, identity)
    if redis_err then
      meta.redis_error = redis_err
    elseif redis_policy then
      meta.policy_source = redis_meta.policy_source or "redis"
      meta.policy_scope = redis_meta.policy_scope or meta.policy_scope
      meta.policy_id = redis_meta.policy_id or meta.policy_id
      meta.policy_key = redis_meta.policy_key
      return redis_policy, meta
    else
      meta.policy_source = "redis_miss"
    end
  end

  if conf and type(conf.policy) == "table" then
    meta.policy_source = "config"
    return conf.policy, meta
  end

  return nil, meta
end

local function apply_failure_strategy(conf, params)
  local strategy = failure_control.resolve_failure_strategy(conf)
  local deny_status = failure_control.resolve_failure_deny_status(conf)
  local decision_value = strategy == "fail_closed" and "deny" or "allow"
  local reason_prefix = params.reason_prefix or "redis_failure"
  local reason = reason_prefix .. "_" .. strategy

  emit_failure_alarm({
    route_id = params.route_id,
    reason = reason,
    strategy = strategy,
    deny_status = deny_status,
    source = params.failure_source,
    redis_error = params.redis_error,
    policy_source = params.policy_source,
  })

  commit_runtime_ctx(build_runtime_ctx({
    identity = params.identity,
    identity_source = params.identity_source,
    units = params.units or 0,
    current_usage = params.current_usage or 0,
    decision = decision_value,
    reason = reason,
    route_id = params.route_id,
    policy_version = params.policy_version,
    policy_source = params.policy_source or "redis_failure",
    policy_key = params.policy_key,
    usage_scope = params.usage_scope,
    usage_id = params.usage_id,
    usage_month = params.usage_month or 0,
    usage_day = params.usage_day or 0,
    usage_keys = params.usage_keys or {},
    ttl_seconds = params.ttl_seconds or {},
    redis_error = params.redis_error,
    usage_error = params.usage_error,
    increment_error = params.increment_error,
    atomic = params.atomic or false,
    atomic_error = params.atomic_error,
    failure_strategy = strategy,
    failure_source = params.failure_source,
    failure_deny_status = deny_status,
    redis_circuit_open = params.redis_circuit_open or false,
    meta = params.meta or {
      budget = nil,
      projected_usage = nil,
    },
  }))

  if decision_value == "deny" then
    return exit_with_status(deny_status, {
      message = "redis is unavailable",
      reason = reason,
    }), true
  end

  return nil, true
end

-- 13.4 단계 access 실행 훅.
-- Redis 정책 조회와 month/day 사용량 카운터를 반영해 차단 여부를 결정한다.
function plugin:access(conf)
  local identity, identity_source = extract_identity(conf)
  local route_id = get_route_id()
  local redis_client = nil
  local redis_is_factory_client = false
  local redis_error = nil
  local redis_requested = should_use_redis(conf)
  local redis_had_failure = false

  local ok_identity = policy_model.validate_identity(identity)
  if not ok_identity then
    commit_runtime_ctx(build_runtime_ctx({
      identity = identity,
      identity_source = identity_source,
      units = 0,
      decision = "deny",
      reason = "identity_missing",
      route_id = route_id,
      policy_version = nil,
      meta = {
        budget = nil,
        projected_usage = nil,
      },
    }))

    return exit_with_status(429, {
      message = "required identity is missing",
      reason = "identity_missing",
    })
  end

  if redis_requested then
    local circuit_open, circuit_meta = failure_control.is_circuit_open(conf)
    if circuit_open then
      local response = nil
      response = select(1, apply_failure_strategy(conf, {
        identity = identity,
        identity_source = identity_source,
        route_id = route_id,
        reason_prefix = "redis_circuit_open",
        failure_source = circuit_meta and circuit_meta.source or "redis_circuit_open",
        redis_error = "redis circuit breaker is open",
        policy_source = "circuit_open",
        redis_circuit_open = true,
      }))
      return response
    end

    redis_client, redis_error, redis_is_factory_client = redis_store.open_client(conf)
    if not redis_client then
      redis_had_failure = true
      failure_control.record_redis_result(conf, false)
      local response = nil
      response = select(1, apply_failure_strategy(conf, {
        identity = identity,
        identity_source = identity_source,
        route_id = route_id,
        reason_prefix = "redis_connect_failed",
        failure_source = "redis_connect",
        redis_error = redis_error,
        policy_source = "redis_connect_error",
      }))
      return response
    end
  end

  local raw_policy, policy_meta = resolve_policy(conf, identity, redis_client)
  if policy_meta and policy_meta.redis_error and not redis_error then
    redis_error = policy_meta.redis_error
  end

  if redis_requested and is_non_empty_string(redis_error) then
    redis_had_failure = true
    failure_control.record_redis_result(conf, false)
  end

  local policy_version = resolve_policy_version(raw_policy)
  if not raw_policy then
    if redis_requested and is_non_empty_string(redis_error) then
      close_redis_client(redis_client, redis_is_factory_client)
      local response = nil
      response = select(1, apply_failure_strategy(conf, {
        identity = identity,
        identity_source = identity_source,
        route_id = route_id,
        reason_prefix = "redis_policy_fetch_failed",
        failure_source = "redis_policy_fetch",
        redis_error = redis_error,
        policy_source = policy_meta and policy_meta.policy_source or "redis_error",
        policy_key = policy_meta and policy_meta.policy_key or nil,
        usage_scope = policy_meta and policy_meta.policy_scope or nil,
        usage_id = policy_meta and policy_meta.policy_id or nil,
      }))
      return response
    end

    local deny_when_missing = conf and conf.redis_policy_required == true
    local decision_result = deny_when_missing and "deny" or "allow"

    commit_runtime_ctx(build_runtime_ctx({
      identity = identity,
      identity_source = identity_source,
      units = 0,
      decision = decision_result,
      reason = "policy_missing",
      route_id = route_id,
      policy_version = nil,
      policy_source = policy_meta and policy_meta.policy_source or "none",
      policy_key = policy_meta and policy_meta.policy_key or nil,
      usage_scope = policy_meta and policy_meta.policy_scope or nil,
      usage_id = policy_meta and policy_meta.policy_id or nil,
      redis_error = redis_error,
      meta = {
        budget = nil,
        projected_usage = nil,
      },
    }))

    close_redis_client(redis_client, redis_is_factory_client)

    if deny_when_missing then
      return exit_with_status(429, {
        message = "policy is missing",
        reason = "policy_missing",
      })
    end

    if redis_requested and not redis_had_failure then
      failure_control.record_redis_result(conf, true)
    end
    return
  end

  local normalized_policy, normalize_err = policy_model.normalize_policy(raw_policy)
  if not normalized_policy or normalize_err then
    commit_runtime_ctx(build_runtime_ctx({
      identity = identity,
      identity_source = identity_source,
      units = 0,
      decision = "allow",
      reason = "policy_invalid",
      route_id = route_id,
      policy_version = policy_version,
      policy_source = policy_meta and policy_meta.policy_source or "none",
      policy_key = policy_meta and policy_meta.policy_key or nil,
      usage_scope = policy_meta and policy_meta.policy_scope or nil,
      usage_id = policy_meta and policy_meta.policy_id or nil,
      redis_error = redis_error,
      meta = {
        budget = nil,
        projected_usage = nil,
      },
    }))

    close_redis_client(redis_client, redis_is_factory_client)
    if redis_requested and not redis_had_failure then
      failure_control.record_redis_result(conf, true)
    end
    return
  end

  local req_ctx = {
    route_id = route_id,
    service = get_service_name(),
    path = get_path(),
    method = get_method(),
  }

  local matched_rule, matched_source = route_matcher.match_rule(req_ctx, normalized_policy)
  local units, _, units_err = unit_calculator.compute_units({
    matched_rule = matched_rule,
    matched_source = matched_source,
  }, normalized_policy, identity)

  if units_err then
    commit_runtime_ctx(build_runtime_ctx({
      identity = identity,
      identity_source = identity_source,
      units = 0,
      decision = "allow",
      reason = "units_calculation_failed",
      route_id = route_id,
      policy_version = policy_version,
      policy_source = policy_meta and policy_meta.policy_source or "none",
      policy_key = policy_meta and policy_meta.policy_key or nil,
      usage_scope = policy_meta and policy_meta.policy_scope or nil,
      usage_id = policy_meta and policy_meta.policy_id or nil,
      redis_error = redis_error,
      meta = {
        budget = nil,
        projected_usage = nil,
      },
    }))

    close_redis_client(redis_client, redis_is_factory_client)
    if redis_requested and not redis_had_failure then
      failure_control.record_redis_result(conf, true)
    end
    return
  end

  local current_epoch = redis_store.current_epoch(conf)
  local usage_scope = policy_meta and policy_meta.policy_scope or nil
  local usage_id = policy_meta and policy_meta.policy_id or nil
  local usage_keys = {}
  local ttl_seconds = {}
  local usage_month = 0
  local usage_day = 0
  local usage_error = nil
  local current_usage = 0
  local increment_error = nil
  local atomic_script_sha = nil
  local month_before = nil
  local day_before = nil
  local month_after = nil
  local day_after = nil
  local exceeded_by = nil
  local atomic_enabled = not (conf and conf.redis_atomic_enabled == false)
  local deny_status = decision.resolve_deny_status(conf, normalized_policy)

  local budget = resolve_budget(matched_rule, normalized_policy)

  if redis_client and atomic_enabled and is_non_empty_string(usage_scope) and is_non_empty_string(usage_id) then
    local atomic_result, atomic_meta, atomic_err = redis_store.atomic_charge_usages(
      redis_client,
      conf,
      usage_scope,
      usage_id,
      units,
      budget,
      current_epoch
    )

    if atomic_err then
      increment_error = atomic_err
      close_redis_client(redis_client, redis_is_factory_client)
      redis_had_failure = true
      failure_control.record_redis_result(conf, false)
      local response = nil
      response = select(1, apply_failure_strategy(conf, {
        identity = identity,
        identity_source = identity_source,
        units = units,
        current_usage = 0,
        route_id = route_id,
        policy_version = policy_version,
        policy_source = policy_meta and policy_meta.policy_source or "none",
        policy_key = policy_meta and policy_meta.policy_key or nil,
        usage_scope = usage_scope,
        usage_id = usage_id,
        usage_month = 0,
        usage_day = 0,
        usage_keys = usage_keys,
        ttl_seconds = ttl_seconds,
        redis_error = redis_error,
        usage_error = usage_error,
        increment_error = increment_error,
        atomic = true,
        atomic_error = atomic_err,
        reason_prefix = "atomic_charge_failed",
        failure_source = "redis_atomic_charge",
        meta = {
          budget = budget,
          projected_usage = units,
        },
      }))
      return response
    end

    usage_keys = atomic_meta.keys or {}
    ttl_seconds = atomic_meta.ttl_seconds or {}
    atomic_script_sha = atomic_meta.script_sha

    month_before = atomic_result.month_before
    day_before = atomic_result.day_before
    month_after = atomic_result.month_after
    day_after = atomic_result.day_after
    exceeded_by = atomic_result.exceeded_by
    current_usage = atomic_result.current_usage_before or 0

    local result = atomic_result.decision
    local reason = atomic_result.reason
    if result == "allow" then
      usage_month = month_after
      usage_day = day_after
    else
      usage_month = month_before
      usage_day = day_before
    end

    commit_runtime_ctx(build_runtime_ctx({
      identity = identity,
      identity_source = identity_source,
      units = units,
      current_usage = current_usage,
      decision = result,
      reason = reason,
      route_id = route_id,
      policy_version = policy_version,
      policy_source = policy_meta and policy_meta.policy_source or "none",
      policy_key = policy_meta and policy_meta.policy_key or nil,
      usage_scope = usage_scope,
      usage_id = usage_id,
      usage_month = usage_month,
      usage_day = usage_day,
      usage_keys = usage_keys,
      ttl_seconds = ttl_seconds,
      redis_error = redis_error,
      usage_error = usage_error,
      atomic = true,
      atomic_script_sha = atomic_script_sha,
      month_before = month_before,
      day_before = day_before,
      month_after = month_after,
      day_after = day_after,
      exceeded_by = exceeded_by,
      meta = {
        budget = budget,
        projected_usage = atomic_result.projected_usage,
      },
    }))

    if result == "deny" then
      close_redis_client(redis_client, redis_is_factory_client)
      if redis_requested and not redis_had_failure then
        failure_control.record_redis_result(conf, true)
      end
      return exit_with_status(deny_status, {
        message = "budget exceeded",
        reason = reason,
        units = units,
      })
    end

    close_redis_client(redis_client, redis_is_factory_client)
    if redis_requested and not redis_had_failure then
      failure_control.record_redis_result(conf, true)
    end
    return
  end

  -- Redis 원자 경로를 사용하지 못할 때의 호환 경로다.
  local result, meta, decision_err = decision.make_decision(current_usage, budget, units, conf, normalized_policy)
  if decision_err then
    commit_runtime_ctx(build_runtime_ctx({
      identity = identity,
      identity_source = identity_source,
      units = units,
      current_usage = current_usage,
      decision = "allow",
      reason = "decision_error",
      route_id = route_id,
      policy_version = policy_version,
      policy_source = policy_meta and policy_meta.policy_source or "none",
      policy_key = policy_meta and policy_meta.policy_key or nil,
      usage_scope = usage_scope,
      usage_id = usage_id,
      usage_month = usage_month,
      usage_day = usage_day,
      usage_keys = usage_keys,
      ttl_seconds = ttl_seconds,
      redis_error = redis_error,
      usage_error = usage_error,
      meta = {
        budget = budget,
        projected_usage = current_usage + units,
      },
    }))

    close_redis_client(redis_client, redis_is_factory_client)
    if redis_requested and not redis_had_failure then
      failure_control.record_redis_result(conf, true)
    end
    return
  end

  if result == "allow" and redis_client and is_non_empty_string(usage_scope) and is_non_empty_string(usage_id) then
    local increased, increased_meta, incr_err = redis_store.increment_usages(
      redis_client,
      conf,
      usage_scope,
      usage_id,
      units,
      current_epoch
    )
    if incr_err then
      increment_error = incr_err
      close_redis_client(redis_client, redis_is_factory_client)
      redis_had_failure = true
      failure_control.record_redis_result(conf, false)
      local response = nil
      response = select(1, apply_failure_strategy(conf, {
        identity = identity,
        identity_source = identity_source,
        units = units,
        current_usage = current_usage,
        route_id = route_id,
        policy_version = policy_version,
        policy_source = policy_meta and policy_meta.policy_source or "none",
        policy_key = policy_meta and policy_meta.policy_key or nil,
        usage_scope = usage_scope,
        usage_id = usage_id,
        usage_month = usage_month,
        usage_day = usage_day,
        usage_keys = usage_keys,
        ttl_seconds = ttl_seconds,
        redis_error = redis_error,
        usage_error = usage_error,
        increment_error = increment_error,
        atomic = false,
        reason_prefix = "usage_increment_failed",
        failure_source = "redis_increment",
        meta = {
          budget = budget,
          projected_usage = current_usage + units,
        },
      }))
      return response
    elseif type(increased) == "table" then
      usage_month = increased.month or usage_month
      usage_day = increased.day or usage_day
      usage_keys = increased_meta and increased_meta.keys or usage_keys
      ttl_seconds = increased_meta and increased_meta.ttl_seconds or ttl_seconds
      month_before = increased_meta and increased_meta.before and increased_meta.before.month or month_before
      day_before = increased_meta and increased_meta.before and increased_meta.before.day or day_before
      month_after = usage_month
      day_after = usage_day
    end
  end

  commit_runtime_ctx(build_runtime_ctx({
    identity = identity,
    identity_source = identity_source,
    units = units,
    current_usage = current_usage,
    decision = result,
    reason = meta and meta.reason or "unknown",
    route_id = route_id,
    policy_version = policy_version,
    policy_source = policy_meta and policy_meta.policy_source or "none",
    policy_key = policy_meta and policy_meta.policy_key or nil,
    usage_scope = usage_scope,
    usage_id = usage_id,
    usage_month = usage_month,
    usage_day = usage_day,
    usage_keys = usage_keys,
    ttl_seconds = ttl_seconds,
    redis_error = redis_error,
    usage_error = usage_error,
    increment_error = increment_error,
    atomic = false,
    month_before = month_before,
    day_before = day_before,
    month_after = month_after,
    day_after = day_after,
    exceeded_by = exceeded_by,
    meta = meta,
  }))

  if result == "deny" then
    local fallback_deny_status = meta and meta.deny_status or 429
    close_redis_client(redis_client, redis_is_factory_client)
    if redis_requested and not redis_had_failure then
      failure_control.record_redis_result(conf, true)
    end
    return exit_with_status(fallback_deny_status, {
      message = "budget exceeded",
      reason = meta.reason,
      units = units,
    })
  end

  close_redis_client(redis_client, redis_is_factory_client)
  if redis_requested and not redis_had_failure then
    failure_control.record_redis_result(conf, true)
  end
end

-- 13.3 단계 log 실행 훅.
-- access 단계에서 저장한 핵심 필드만 구조화 로그로 남긴다.
function plugin:log(conf)
  if conf and conf.audit_log_enabled == false then
    return
  end

  local shared = get_ctx_shared()
  if not shared or type(shared.cost_quota_ctx) ~= "table" then
    return
  end

  local runtime_ctx = shared.cost_quota_ctx
  local identity = runtime_ctx.identity or {}

  local audit_event = {
    client_id = identity.client_id,
    org_id = identity.org_id,
    route_id = runtime_ctx.route_id,
    units = runtime_ctx.units,
    remaining = runtime_ctx.remaining,
    policy_version = runtime_ctx.policy_version,
    policy_source = runtime_ctx.policy_source,
    decision = runtime_ctx.decision,
    reason = runtime_ctx.reason,
  }

  log_notice("cost_quota_audit " .. encode_json(audit_event))
end

return plugin
