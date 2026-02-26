-- 핸들러 모듈.
-- 플러그인 진입점.
-- 현재 단계에서는 기본 모듈만 연결하며 레디스/캐시 연동은 이후 단계에서 추가한다.
local policy_model = require("kong.plugins.kong-cost-quota.policy_model")
local route_matcher = require("kong.plugins.kong-cost-quota.route_matcher")
local unit_calculator = require("kong.plugins.kong-cost-quota.unit_calculator")
local decision = require("kong.plugins.kong-cost-quota.decision")

local plugin = {
  PRIORITY = 1000,
  VERSION = "0.1.0",
}

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

-- 13.2 단계용 최소 요청 훅.
-- 정책이 제공되면 식별자를 검증하고 유닛을 계산한다.
function plugin:access(conf)
  local identity = {
    client_id = get_header("x-client-id"),
    org_id = get_header("x-org-id"),
    plan = get_header("x-plan"),
  }

  local ok_identity = policy_model.validate_identity(identity)
  if not ok_identity then
    -- 식별자 강제 검증의 세부 로직은 13.3 단계에서 완료한다.
    return
  end

  local policy = conf and conf.policy
  if not policy then
    return
  end

  local normalized_policy, normalize_err = policy_model.normalize_policy(policy)
  if not normalized_policy or normalize_err then
    return
  end

  local req_ctx = {
    route_id = get_route_id(),
    service = get_service_name(),
    path = kong and kong.request and kong.request.get_path and kong.request.get_path() or "",
    method = kong and kong.request and kong.request.get_method and kong.request.get_method() or "GET",
  }

  local matched_rule, matched_source = route_matcher.match_rule(req_ctx, normalized_policy)
  local units, _, units_err = unit_calculator.compute_units({
    matched_rule = matched_rule,
    matched_source = matched_source,
  }, normalized_policy, identity)
  if units_err then
    return
  end

  -- 예산 결정 호출 경로만 준비하며 실제 사용량 카운터는 이후 단계에서 추가한다.
  decision.make_decision(0, nil, units, conf, normalized_policy)
end

return plugin
