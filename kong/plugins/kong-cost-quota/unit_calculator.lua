-- 유닛 계산 모듈.
-- 선택된 규칙과 배수 컨텍스트를 기준으로 차감 유닛을 계산한다.
local M = {}

local function to_non_negative_number(value, default_value)
  if type(value) ~= "number" then
    return default_value
  end
  if value < 0 then
    return nil
  end
  return value
end

-- 플랜별 배수 오버라이드가 있으면 우선 적용한다.
local function resolve_plan_multiplier(rule, policy, identity)
  local plan_multiplier = rule.plan_multiplier or 1.0
  local plan = identity and identity.plan

  if type(plan) == "string" and policy and type(policy.plan_multipliers) == "table" then
    local overridden = policy.plan_multipliers[plan]
    if type(overridden) == "number" then
      return overridden
    end
  end

  return plan_multiplier
end

-- 반환값: 계산 유닛 수, 상세 정보, 오류.
function M.compute_units(ctx, policy, identity)
  local rule = ctx and ctx.matched_rule or (policy and policy.default)
  if type(rule) ~= "table" then
    return nil, nil, "matched rule is required"
  end

  local base_weight = to_non_negative_number(rule.base_weight, 1)
  local plan_multiplier = to_non_negative_number(resolve_plan_multiplier(rule, policy, identity), 1.0)

  local time_multiplier = rule.time_multiplier
  if ctx and type(ctx.time_multiplier_override) == "number" then
    time_multiplier = ctx.time_multiplier_override
  end
  time_multiplier = to_non_negative_number(time_multiplier, 1.0)

  local custom_multiplier = rule.custom_multiplier
  if ctx and type(ctx.custom_multiplier_override) == "number" then
    custom_multiplier = ctx.custom_multiplier_override
  end
  custom_multiplier = to_non_negative_number(custom_multiplier, 1.0)

  if not base_weight or not plan_multiplier or not time_multiplier or not custom_multiplier then
    return nil, nil, "all multipliers must be >= 0"
  end

  local raw_units = base_weight * plan_multiplier * time_multiplier * custom_multiplier
  local units = math.ceil(raw_units)
  if units < 0 then
    units = 0
  end

  local detail = {
    base_weight = base_weight,
    plan_multiplier = plan_multiplier,
    time_multiplier = time_multiplier,
    custom_multiplier = custom_multiplier,
    raw_units = raw_units,
    rounded_units = units,
    source = ctx and ctx.matched_source or "unknown",
  }

  return units, detail, nil
end

return M
