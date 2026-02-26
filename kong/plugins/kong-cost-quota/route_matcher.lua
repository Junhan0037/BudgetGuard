-- 라우트 매처 모듈.
-- 요구 우선순위에 따라 매칭 규칙을 선택한다.
local M = {}

local function starts_with(text, prefix)
  if type(text) ~= "string" or type(prefix) ~= "string" then
    return false
  end
  return text:sub(1, #prefix) == prefix
end

local function match_route_id(req_ctx, rules)
  if type(rules) ~= "table" or type(req_ctx) ~= "table" then
    return nil
  end
  if type(req_ctx.route_id) ~= "string" or req_ctx.route_id == "" then
    return nil
  end
  return rules[req_ctx.route_id]
end

local function match_service_prefix(req_ctx, rules)
  if type(rules) ~= "table" or type(req_ctx) ~= "table" then
    return nil
  end

  for _, rule in ipairs(rules) do
    if req_ctx.service == rule.service and starts_with(req_ctx.path, rule.path_prefix) then
      return rule
    end
  end

  return nil
end

local function match_method_regex(req_ctx, rules)
  if type(rules) ~= "table" or type(req_ctx) ~= "table" then
    return nil
  end

  local method = req_ctx.method and string.upper(req_ctx.method) or nil
  local path = req_ctx.path or ""

  for _, rule in ipairs(rules) do
    if method == rule.method then
      local ok, found = pcall(string.find, path, rule.path_regex)
      if ok and found then
        return rule
      end
    end
  end

  return nil
end

-- 반환값: 매칭된 규칙과 매칭 출처.
-- 매칭 출처 값은 라우트, 서비스 경로 접두어, 메서드 정규식, 기본 규칙, 미매칭 중 하나다.
function M.match_rule(req_ctx, policy)
  local rules = policy and policy.rules or {}

  local by_route_id = rules.by_route_id or {}
  local route_rule = match_route_id(req_ctx, by_route_id)
  if route_rule then
    return route_rule, "route_id"
  end

  local by_service_path_prefix = rules.by_service_path_prefix or {}
  local service_rule = match_service_prefix(req_ctx, by_service_path_prefix)
  if service_rule then
    return service_rule, "service_path_prefix"
  end

  local by_method_path_regex = rules.by_method_path_regex or {}
  local method_rule = match_method_regex(req_ctx, by_method_path_regex)
  if method_rule then
    return method_rule, "method_path_regex"
  end

  if policy and policy.default then
    return policy.default, "default"
  end

  return nil, "none"
end

return M
