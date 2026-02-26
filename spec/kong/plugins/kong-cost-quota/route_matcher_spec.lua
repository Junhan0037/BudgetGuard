-- 라우트 매칭 우선순위에 대한 단위 테스트.
local route_matcher = require("kong.plugins.kong-cost-quota.route_matcher")

describe("route_matcher", function()
  local policy = {
    default = { base_weight = 1, plan_multiplier = 1, time_multiplier = 1, custom_multiplier = 1 },
    rules = {
      by_route_id = {
        ["route-123"] = { base_weight = 10, plan_multiplier = 1, time_multiplier = 1, custom_multiplier = 1 },
      },
      by_service_path_prefix = {
        {
          service = "svc-a",
          path_prefix = "/search",
          base_weight = 5,
          plan_multiplier = 1,
          time_multiplier = 1,
          custom_multiplier = 1,
        },
      },
      by_method_path_regex = {
        {
          method = "GET",
          path_regex = "^/search",
          base_weight = 3,
          plan_multiplier = 1,
          time_multiplier = 1,
          custom_multiplier = 1,
        },
      },
    },
  }

  it("matches route_id first", function()
    local matched, source = route_matcher.match_rule({
      route_id = "route-123",
      service = "svc-a",
      path = "/search/item",
      method = "GET",
    }, policy)

    assert.is_table(matched)
    assert.are.equal("route_id", source)
    assert.are.equal(10, matched.base_weight)
  end)

  it("matches service + path_prefix before method + path_regex", function()
    local matched, source = route_matcher.match_rule({
      service = "svc-a",
      path = "/search/item",
      method = "GET",
    }, policy)

    assert.is_table(matched)
    assert.are.equal("service_path_prefix", source)
    assert.are.equal(5, matched.base_weight)
  end)

  it("falls back to default rule", function()
    local matched, source = route_matcher.match_rule({
      service = "svc-x",
      path = "/unknown",
      method = "POST",
    }, policy)

    assert.is_table(matched)
    assert.are.equal("default", source)
    assert.are.equal(1, matched.base_weight)
  end)
end)
