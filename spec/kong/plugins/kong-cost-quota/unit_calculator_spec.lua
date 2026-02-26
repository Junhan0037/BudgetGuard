-- 유닛 계산식에 대한 단위 테스트.
local unit_calculator = require("kong.plugins.kong-cost-quota.unit_calculator")

-- 부동소수점 계산 오차를 허용하기 위한 공용 비교 함수.
local function assert_close(expected, actual, epsilon)
  local diff = math.abs(expected - actual)
  assert.is_true(
    diff <= (epsilon or 1e-9),
    string.format("expected %.12f, got %.12f (diff=%.12f)", expected, actual, diff)
  )
end

describe("unit_calculator", function()
  it("computes units with base formula", function()
    local units, detail, err = unit_calculator.compute_units({
      matched_rule = {
        base_weight = 10,
        plan_multiplier = 0.8,
        time_multiplier = 1.2,
        custom_multiplier = 1.5,
      },
      matched_source = "route_id",
    }, {
      plan_multipliers = {},
    }, {
      client_id = "client-1",
      plan = "pro",
    })

    assert.is_nil(err)
    assert.are.equal(15, units)
    assert_close(14.4, detail.raw_units)
  end)

  it("applies plan-specific multiplier override", function()
    local units, detail, err = unit_calculator.compute_units({
      matched_rule = {
        base_weight = 10,
        plan_multiplier = 1.0,
        time_multiplier = 1.0,
        custom_multiplier = 1.0,
      },
    }, {
      plan_multipliers = {
        pro = 0.5,
      },
    }, {
      client_id = "client-1",
      plan = "pro",
    })

    assert.is_nil(err)
    assert.are.equal(5, units)
    assert.are.equal(0.5, detail.plan_multiplier)
  end)

  it("rejects negative values", function()
    local units, detail, err = unit_calculator.compute_units({
      matched_rule = {
        base_weight = -1,
        plan_multiplier = 1.0,
        time_multiplier = 1.0,
        custom_multiplier = 1.0,
      },
    }, {}, {})

    assert.is_nil(units)
    assert.is_nil(detail)
    assert.is_truthy(err)
  end)
end)
