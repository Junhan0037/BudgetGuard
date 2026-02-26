-- 차단 상태 코드와 예산 결정 로직에 대한 단위 테스트.
local decision = require("kong.plugins.kong-cost-quota.decision")

describe("decision", function()
  it("uses 429 as default deny status", function()
    local code = decision.resolve_deny_status({}, {})
    assert.are.equal(429, code)
  end)

  it("uses policy deny status before config", function()
    local code = decision.resolve_deny_status({
      deny_status_code = 429,
    }, {
      deny_status_code = 402,
    })
    assert.are.equal(402, code)
  end)

  it("allows when within budget", function()
    local result, meta, err = decision.make_decision(10, 20, 5, {}, {})
    assert.is_nil(err)
    assert.are.equal("allow", result)
    assert.are.equal("within_budget", meta.reason)
  end)

  it("denies when budget is exceeded", function()
    local result, meta, err = decision.make_decision(10, 12, 3, {
      deny_status_code = 429,
    }, {})

    assert.is_nil(err)
    assert.are.equal("deny", result)
    assert.are.equal("budget_exceeded", meta.reason)
    assert.are.equal(429, meta.deny_status)
  end)
end)
