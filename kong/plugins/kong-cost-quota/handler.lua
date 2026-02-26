local policy_model = require("kong.plugins.kong-cost-quota.policy_model")
local route_matcher = require("kong.plugins.kong-cost-quota.route_matcher")
local unit_calculator = require("kong.plugins.kong-cost-quota.unit_calculator")
local decision = require("kong.plugins.kong-cost-quota.decision")

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

local function exit_with_status(status_code, body)
  if kong and kong.response and kong.response.exit then
    return kong.response.exit(status_code, body)
  end
  return {
    status = status_code,
    body = body,
  }
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
    decision = params.decision or "allow",
    reason = params.reason or "unknown",
    route_id = params.route_id,
    remaining = remaining,
    policy_version = params.policy_version,
  }
end

-- 13.3 단계 access 실행 훅.
-- identity를 우선순위로 추출하고 유닛 계산 후 허용/차단을 결정한다.
function plugin:access(conf)
  local identity, identity_source = extract_identity(conf)
  local route_id = get_route_id()
  local policy = conf and conf.policy or nil
  local policy_version = resolve_policy_version(policy)

  local ok_identity = policy_model.validate_identity(identity)
  if not ok_identity then
    set_runtime_ctx(build_runtime_ctx({
      identity = identity,
      identity_source = identity_source,
      units = 0,
      decision = "deny",
      reason = "identity_missing",
      route_id = route_id,
      policy_version = policy_version,
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

  if not policy then
    set_runtime_ctx(build_runtime_ctx({
      identity = identity,
      identity_source = identity_source,
      units = 0,
      decision = "allow",
      reason = "policy_missing",
      route_id = route_id,
      policy_version = nil,
      meta = {
        budget = nil,
        projected_usage = nil,
      },
    }))
    return
  end

  local normalized_policy, normalize_err = policy_model.normalize_policy(policy)
  if not normalized_policy or normalize_err then
    set_runtime_ctx(build_runtime_ctx({
      identity = identity,
      identity_source = identity_source,
      units = 0,
      decision = "allow",
      reason = "policy_invalid",
      route_id = route_id,
      policy_version = policy_version,
      meta = {
        budget = nil,
        projected_usage = nil,
      },
    }))
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
    set_runtime_ctx(build_runtime_ctx({
      identity = identity,
      identity_source = identity_source,
      units = 0,
      decision = "allow",
      reason = "units_calculation_failed",
      route_id = route_id,
      policy_version = policy_version,
      meta = {
        budget = nil,
        projected_usage = nil,
      },
    }))
    return
  end

  local budget = resolve_budget(matched_rule, normalized_policy)
  local result, meta, decision_err = decision.make_decision(0, budget, units, conf, normalized_policy)
  if decision_err then
    set_runtime_ctx(build_runtime_ctx({
      identity = identity,
      identity_source = identity_source,
      units = units,
      decision = "allow",
      reason = "decision_error",
      route_id = route_id,
      policy_version = policy_version,
      meta = {
        budget = budget,
        projected_usage = units,
      },
    }))
    return
  end

  set_runtime_ctx(build_runtime_ctx({
    identity = identity,
    identity_source = identity_source,
    units = units,
    decision = result,
    reason = meta and meta.reason or "unknown",
    route_id = route_id,
    policy_version = policy_version,
    meta = meta,
  }))

  if result == "deny" then
    local deny_status = meta and meta.deny_status or 429
    return exit_with_status(deny_status, {
      message = "budget exceeded",
      reason = meta.reason,
      units = units,
    })
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
    decision = runtime_ctx.decision,
    reason = runtime_ctx.reason,
  }

  log_notice("cost_quota_audit " .. encode_json(audit_event))
end

return plugin
