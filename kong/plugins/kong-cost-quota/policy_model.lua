-- 정책 모델 모듈.
-- 결정 로직에서 사용하기 전에 정책 페이로드를 정규화하고 검증한다.
local M = {}

-- 선택 입력 배수 항목이 없으면 안전 기본값을 적용한다.
local SAFE_DEFAULTS = {
  base_weight = 1,
  plan_multiplier = 1.0,
  time_multiplier = 1.0,
  custom_multiplier = 1.0,
}

local VALID_DENY_STATUS_CODES = {
  [402] = true,
  [429] = true,
}

local function is_non_empty_string(value)
  return type(value) == "string" and value:match("%S") ~= nil
end

local function push_error(errors, message)
  errors[#errors + 1] = message
end

local function validate_non_negative_number(value, field_name, errors)
  if type(value) ~= "number" then
    push_error(errors, field_name .. " must be a number")
    return nil
  end

  if value < 0 then
    push_error(errors, field_name .. " must be >= 0")
    return nil
  end

  return value
end

-- 초기 방어를 위해 루아 패턴 문법을 검증한다.
-- 실행 환경에서는 이후 정규식 전용 검증으로 대체할 수 있다.
local function validate_lua_pattern(pattern, field_name, errors)
  if not is_non_empty_string(pattern) then
    push_error(errors, field_name .. " must be a non-empty string")
    return
  end

  local ok = pcall(string.find, "", pattern)
  if not ok then
    push_error(errors, field_name .. " is not a valid pattern")
  end
end

local function normalize_rule(rule, defaults, context, errors)
  if type(rule) ~= "table" then
    push_error(errors, context .. " must be an object")
    return nil
  end

  local base_weight = rule.base_weight
  if base_weight == nil then
    base_weight = SAFE_DEFAULTS.base_weight
  end
  base_weight = validate_non_negative_number(base_weight, context .. ".base_weight", errors)

  local plan_multiplier = rule.plan_multiplier
  if plan_multiplier == nil then
    plan_multiplier = defaults.plan_multiplier
  end
  plan_multiplier = validate_non_negative_number(plan_multiplier, context .. ".plan_multiplier", errors)

  local time_multiplier = rule.time_multiplier
  if time_multiplier == nil then
    time_multiplier = defaults.time_multiplier
  end
  time_multiplier = validate_non_negative_number(time_multiplier, context .. ".time_multiplier", errors)

  local custom_multiplier = rule.custom_multiplier
  if custom_multiplier == nil then
    custom_multiplier = defaults.custom_multiplier
  end
  custom_multiplier = validate_non_negative_number(custom_multiplier, context .. ".custom_multiplier", errors)

  -- budget은 선택 항목이며, 지정된 경우 음수가 아니어야 한다.
  local budget = nil
  if rule.budget ~= nil then
    budget = validate_non_negative_number(rule.budget, context .. ".budget", errors)
  end

  if not base_weight or not plan_multiplier or not time_multiplier or not custom_multiplier then
    return nil
  end

  return {
    base_weight = base_weight,
    plan_multiplier = plan_multiplier,
    time_multiplier = time_multiplier,
    custom_multiplier = custom_multiplier,
    budget = budget,
  }
end

local function normalize_route_rules(raw_route_rules, defaults, errors)
  local normalized = {}

  if raw_route_rules == nil then
    return normalized
  end

  if type(raw_route_rules) ~= "table" then
    push_error(errors, "rules.by_route_id must be an object")
    return normalized
  end

  for route_id, rule in pairs(raw_route_rules) do
    if not is_non_empty_string(route_id) then
      push_error(errors, "rules.by_route_id key must be a non-empty string")
    else
      local normalized_rule = normalize_rule(rule, defaults, "rules.by_route_id[" .. route_id .. "]", errors)
      if normalized_rule then
        normalized_rule.route_id = route_id
        normalized[route_id] = normalized_rule
      end
    end
  end

  return normalized
end

local function normalize_service_prefix_rules(raw_rules, defaults, errors)
  local normalized = {}

  if raw_rules == nil then
    return normalized
  end

  if type(raw_rules) ~= "table" then
    push_error(errors, "rules.by_service_path_prefix must be an array")
    return normalized
  end

  for index, rule in ipairs(raw_rules) do
    local context = "rules.by_service_path_prefix[" .. index .. "]"
    local normalized_rule = normalize_rule(rule, defaults, context, errors)
    if normalized_rule then
      if not is_non_empty_string(rule.service) then
        push_error(errors, context .. ".service must be a non-empty string")
      elseif not is_non_empty_string(rule.path_prefix) then
        push_error(errors, context .. ".path_prefix must be a non-empty string")
      else
        normalized_rule.service = rule.service
        normalized_rule.path_prefix = rule.path_prefix
        normalized[#normalized + 1] = normalized_rule
      end
    end
  end

  return normalized
end

local function normalize_method_regex_rules(raw_rules, defaults, errors)
  local normalized = {}

  if raw_rules == nil then
    return normalized
  end

  if type(raw_rules) ~= "table" then
    push_error(errors, "rules.by_method_path_regex must be an array")
    return normalized
  end

  for index, rule in ipairs(raw_rules) do
    local context = "rules.by_method_path_regex[" .. index .. "]"
    local normalized_rule = normalize_rule(rule, defaults, context, errors)
    if normalized_rule then
      local error_count_before = #errors
      if not is_non_empty_string(rule.method) then
        push_error(errors, context .. ".method must be a non-empty string")
      else
        validate_lua_pattern(rule.path_regex, context .. ".path_regex", errors)
      end

      if #errors == error_count_before and is_non_empty_string(rule.method) and is_non_empty_string(rule.path_regex) then
        normalized_rule.method = string.upper(rule.method)
        normalized_rule.path_regex = rule.path_regex
        normalized[#normalized + 1] = normalized_rule
      end
    end
  end

  return normalized
end

local function normalize_plan_multipliers(raw_map, errors)
  local normalized = {}

  if raw_map == nil then
    return normalized
  end

  if type(raw_map) ~= "table" then
    push_error(errors, "plan_multipliers must be an object")
    return normalized
  end

  for plan, value in pairs(raw_map) do
    if not is_non_empty_string(plan) then
      push_error(errors, "plan_multipliers key must be a non-empty string")
    else
      local validated = validate_non_negative_number(value, "plan_multipliers[" .. plan .. "]", errors)
      if validated then
        normalized[plan] = validated
      end
    end
  end

  return normalized
end

-- 반환값: 정규화된 정책 또는 오류 문자열.
function M.normalize_policy(raw_policy)
  if type(raw_policy) ~= "table" then
    return nil, "policy must be an object"
  end

  local errors = {}
  if raw_policy.deny_status_code ~= nil and not VALID_DENY_STATUS_CODES[raw_policy.deny_status_code] then
    push_error(errors, "deny_status_code must be one of 402 or 429")
  end

  if raw_policy.rules ~= nil and type(raw_policy.rules) ~= "table" then
    push_error(errors, "rules must be an object")
  end

  local defaults = {
    plan_multiplier = raw_policy.default_plan_multiplier or SAFE_DEFAULTS.plan_multiplier,
    time_multiplier = raw_policy.default_time_multiplier or SAFE_DEFAULTS.time_multiplier,
    custom_multiplier = raw_policy.default_custom_multiplier or SAFE_DEFAULTS.custom_multiplier,
  }

  validate_non_negative_number(defaults.plan_multiplier, "default_plan_multiplier", errors)
  validate_non_negative_number(defaults.time_multiplier, "default_time_multiplier", errors)
  validate_non_negative_number(defaults.custom_multiplier, "default_custom_multiplier", errors)

  local normalized_default = normalize_rule(raw_policy.default or {}, defaults, "default", errors)
  local raw_rules = type(raw_policy.rules) == "table" and raw_policy.rules or {}

  local normalized = {
    deny_status_code = raw_policy.deny_status_code,
    default = normalized_default,
    rules = {
      by_route_id = normalize_route_rules(raw_rules.by_route_id, defaults, errors),
      by_service_path_prefix = normalize_service_prefix_rules(raw_rules.by_service_path_prefix, defaults, errors),
      by_method_path_regex = normalize_method_regex_rules(raw_rules.by_method_path_regex, defaults, errors),
    },
    plan_multipliers = normalize_plan_multipliers(raw_policy.plan_multipliers, errors),
  }

  if #errors > 0 then
    return nil, table.concat(errors, "; ")
  end

  return normalized, nil
end

-- 요구사항 기준으로 식별자는 클라이언트 또는 조직 정보 중 하나가 필요하다.
function M.validate_identity(identity)
  if type(identity) ~= "table" then
    return false, "identity must be an object"
  end

  local has_client_id = is_non_empty_string(identity.client_id)
  local has_org_id = is_non_empty_string(identity.org_id)
  if has_client_id or has_org_id then
    return true, nil
  end

  return false, "client_id or org_id is required"
end

function M.safe_defaults()
  return {
    base_weight = SAFE_DEFAULTS.base_weight,
    plan_multiplier = SAFE_DEFAULTS.plan_multiplier,
    time_multiplier = SAFE_DEFAULTS.time_multiplier,
    custom_multiplier = SAFE_DEFAULTS.custom_multiplier,
  }
end

return M
