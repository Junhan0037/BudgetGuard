-- 정책 정규화와 식별자 검증에 대한 단위 테스트.
local policy_model = require("kong.plugins.kong-cost-quota.policy_model")

describe("policy_model", function()
  it("normalizes policy with safe defaults", function()
    local policy, err = policy_model.normalize_policy({
      rules = {},
    })

    assert.is_nil(err)
    assert.is_table(policy)
    assert.are.equal(1, policy.default.base_weight)
    assert.are.equal(1.0, policy.default.plan_multiplier)
    assert.are.equal(1.0, policy.default.time_multiplier)
    assert.are.equal(1.0, policy.default.custom_multiplier)
  end)

  it("rejects invalid multiplier values", function()
    local policy, err = policy_model.normalize_policy({
      default_plan_multiplier = -1,
      rules = {},
    })

    assert.is_nil(policy)
    assert.is_truthy(err)
  end)

  it("normalizes optional budget and validates non-negative value", function()
    local policy_ok, err_ok = policy_model.normalize_policy({
      default = {
        budget = 100,
      },
      rules = {},
    })
    local policy_bad, err_bad = policy_model.normalize_policy({
      default = {
        budget = -1,
      },
      rules = {},
    })

    assert.is_nil(err_ok)
    assert.are.equal(100, policy_ok.default.budget)
    assert.is_nil(policy_bad)
    assert.is_truthy(err_bad)
  end)

  it("rejects unsupported deny status code", function()
    local policy, err = policy_model.normalize_policy({
      deny_status_code = 500,
      rules = {},
    })

    assert.is_nil(policy)
    assert.is_truthy(err)
  end)

  it("validates identity with client_id or org_id", function()
    local ok1 = policy_model.validate_identity({ client_id = "client-1" })
    local ok2 = policy_model.validate_identity({ org_id = "org-1" })
    local ok3 = policy_model.validate_identity({})

    assert.is_true(ok1)
    assert.is_true(ok2)
    assert.is_false(ok3)
  end)
end)
