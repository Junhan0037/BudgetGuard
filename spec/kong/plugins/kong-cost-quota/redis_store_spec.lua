-- 13.4 Redis 저장소 키/TTL/카운터 동작 검증 테스트.
local redis_store = require("kong.plugins.kong-cost-quota.redis_store")

local function new_fake_redis(initial)
  local store = initial and initial.store or {}
  local ttl_map = initial and initial.ttl_map or {}
  local errors = initial and initial.errors or {}

  return {
    store = store,
    ttl_map = ttl_map,
    get = function(_, key)
      if errors.get and errors.get[key] then
        return nil, errors.get[key]
      end
      return store[key], nil
    end,
    incrby = function(_, key, amount)
      local current = tonumber(store[key]) or 0
      local next_value = current + amount
      store[key] = tostring(next_value)
      return next_value, nil
    end,
    ttl = function(_, key)
      return ttl_map[key] or -1, nil
    end,
    expire = function(_, key, seconds)
      ttl_map[key] = tonumber(seconds)
      return 1, nil
    end,
    close = function()
      return true
    end,
  }
end

describe("redis_store", function()
  it("builds policy and usage keys with required format", function()
    local policy_key = redis_store.build_policy_key("prod", "client", "client_123")
    local usage_key = redis_store.build_usage_key("prod", "day", "client", "client_123", "2026-02-26")

    assert.are.equal("policy:prod:client:client_123", policy_key)
    assert.are.equal("usage:prod:day:client:client_123:2026-02-26", usage_key)
  end)

  it("computes UTC bucket and ttl with grace", function()
    local now_epoch = 1772107200 -- 2026-02-26 12:00:00 UTC
    local month_bucket = redis_store.compute_bucket("month", now_epoch)
    local day_bucket = redis_store.compute_bucket("day", now_epoch)
    local month_ttl = redis_store.compute_ttl_seconds("month", now_epoch, 7)
    local day_ttl = redis_store.compute_ttl_seconds("day", now_epoch, 7)

    assert.are.equal("2026-02", month_bucket)
    assert.are.equal("2026-02-26", day_bucket)
    assert.are.equal(820800, month_ttl)
    assert.are.equal(648000, day_ttl)
  end)

  it("falls back from client policy to org policy", function()
    local redis = new_fake_redis({
      store = {
        ["policy:prod:org:org-1"] = [[{"version":"org-v1","default":{"base_weight":1,"plan_multiplier":1,"time_multiplier":1,"custom_multiplier":1,"budget":10},"rules":{}}]],
      },
    })

    local policy, meta, err = redis_store.fetch_policy(redis, {
      redis_env = "prod",
    }, {
      client_id = "client-1",
      org_id = "org-1",
    })

    assert.is_nil(err)
    assert.is_table(policy)
    assert.are.equal("org-v1", policy.version)
    assert.are.equal("policy:prod:org:org-1", meta.policy_key)
    assert.are.equal("org", meta.policy_scope)
    assert.are.equal("org-1", meta.policy_id)
  end)

  it("reads month/day usages with key metadata", function()
    local now_epoch = 1772107200 -- 2026-02-26 12:00:00 UTC
    local redis = new_fake_redis({
      store = {
        ["usage:prod:month:client:client-1:2026-02"] = "5",
        ["usage:prod:day:client:client-1:2026-02-26"] = "2",
      },
    })

    local usages, meta, err = redis_store.read_usages(redis, {
      redis_env = "prod",
      usage_grace_days = 7,
    }, "client", "client-1", now_epoch)

    assert.is_nil(err)
    assert.are.equal(5, usages.month)
    assert.are.equal(2, usages.day)
    assert.are.equal("usage:prod:month:client:client-1:2026-02", meta.keys.month)
    assert.are.equal("usage:prod:day:client:client-1:2026-02-26", meta.keys.day)
    assert.are.equal(820800, meta.ttl_seconds.month)
    assert.are.equal(648000, meta.ttl_seconds.day)
  end)

  it("increases month/day usage and sets ttl when missing", function()
    local now_epoch = 1772107200 -- 2026-02-26 12:00:00 UTC
    local redis = new_fake_redis({
      store = {
        ["usage:prod:month:client:client-1:2026-02"] = "1",
        ["usage:prod:day:client:client-1:2026-02-26"] = "3",
      },
    })

    local updated, meta, err = redis_store.increment_usages(redis, {
      redis_env = "prod",
      usage_grace_days = 7,
    }, "client", "client-1", 2, now_epoch)

    assert.is_nil(err)
    assert.are.equal(3, updated.month)
    assert.are.equal(5, updated.day)
    assert.are.equal(1, meta.before.month)
    assert.are.equal(3, meta.before.day)
    assert.are.equal(820800, redis.ttl_map["usage:prod:month:client:client-1:2026-02"])
    assert.are.equal(648000, redis.ttl_map["usage:prod:day:client:client-1:2026-02-26"])
  end)
end)
