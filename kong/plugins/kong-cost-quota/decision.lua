-- 결정 로직 모듈.
-- 응답 코드 선택과 허용/차단 결정 로직을 담는다.
local M = {}

local VALID_DENY_CODES = {
  [402] = true,
  [429] = true,
}

-- 정책의 차단 상태 코드를 우선 적용하고, 설정 값은 보조값으로 사용한다.
function M.resolve_deny_status(conf, policy)
  if policy and VALID_DENY_CODES[policy.deny_status_code] then
    return policy.deny_status_code
  end

  if conf and VALID_DENY_CODES[conf.deny_status_code] then
    return conf.deny_status_code
  end

  return 429
end

-- 반환값: 결정 결과, 부가 정보, 오류.
function M.make_decision(current_usage, budget, units, conf, policy)
  local usage = tonumber(current_usage) or 0
  local charge_units = tonumber(units) or 0
  local deny_status = M.resolve_deny_status(conf, policy)

  if charge_units < 0 then
    return nil, nil, "units must be >= 0"
  end

  if budget == nil then
    return "allow", {
      reason = "budget_missing",
      deny_status = deny_status,
      current_usage = usage,
      projected_usage = usage + charge_units,
      budget = nil,
    }, nil
  end

  local budget_value = tonumber(budget)
  if not budget_value or budget_value < 0 then
    return nil, nil, "budget must be >= 0"
  end

  local projected = usage + charge_units
  if projected > budget_value then
    return "deny", {
      reason = "budget_exceeded",
      deny_status = deny_status,
      current_usage = usage,
      projected_usage = projected,
      budget = budget_value,
      exceeded_by = projected - budget_value,
    }, nil
  end

  return "allow", {
    reason = "within_budget",
    deny_status = deny_status,
    current_usage = usage,
    projected_usage = projected,
    budget = budget_value,
  }, nil
end

return M
