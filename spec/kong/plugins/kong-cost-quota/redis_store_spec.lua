-- 13.4 Redis 저장소 키/TTL/카운터 동작 검증 테스트.
local redis_store = require("kong.plugins.kong-cost-quota.redis_store")

local function new_fake_redis(initial)
  local store = initial and initial.store or {}
  local ttl_map = initial and initial.ttl_map or {}
  local errors = initial and initial.errors or {}
  local scripts = {}
  local script_sequence = 0
  local noscript_once = initial and initial.noscript_once or false

  -- 테스트용 Redis Lua 실행기.
  local function eval_atomic(month_key, day_key, units, budget_arg, month_ttl, day_ttl)
    local charge_units = tonumber(units) or 0
    local month_before = tonumber(store[month_key]) or 0
    local day_before = tonumber(store[day_key]) or 0
    local current_before = math.max(month_before, day_before)
    local projected_usage = math.max(month_before + charge_units, day_before + charge_units)

    if charge_units < 0 then
      return { "error", "units_must_be_non_negative", 0, 0, 0, 0, 0, 0, 0 }, nil
    end

    if budget_arg ~= nil and budget_arg ~= "" then
      local budget = tonumber(budget_arg)
      if not budget then
        return { "error", "budget_must_be_numeric", month_before, day_before, current_before, projected_usage, month_before, day_before, 0 }, nil
      end

      if (month_before + charge_units) > budget or (day_before + charge_units) > budget then
        return { "deny", "budget_exceeded", month_before, day_before, current_before, projected_usage, month_before, day_before, projected_usage - budget }, nil
      end
    end

    local month_after = month_before + charge_units
    local day_after = day_before + charge_units
    store[month_key] = tostring(month_after)
    store[day_key] = tostring(day_after)

    if (ttl_map[month_key] or -1) < 0 then
      ttl_map[month_key] = tonumber(month_ttl)
    end
    if (ttl_map[day_key] or -1) < 0 then
      ttl_map[day_key] = tonumber(day_ttl)
    end

    local reason = "within_budget"
    if budget_arg == nil or budget_arg == "" then
      reason = "budget_missing"
    end

    return { "allow", reason, month_before, day_before, current_before, projected_usage, month_after, day_after, 0 }, nil
  end

  return {
    store = store,
    ttl_map = ttl_map,
    scripts = scripts,
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
    script = function(_, command, script_body)
      if string.lower(command or "") ~= "load" then
        return nil, "unsupported script command"
      end
      script_sequence = script_sequence + 1
      local sha = "sha-" .. tostring(script_sequence)
      scripts[sha] = script_body
      return sha, nil
    end,
    evalsha = function(_, sha, numkeys, ...)
      if noscript_once then
        noscript_once = false
        return nil, "NOSCRIPT No matching script. Please use EVAL."
      end

      local script_body = scripts[sha]
      if not script_body then
        return nil, "NOSCRIPT No matching script. Please use EVAL."
      end

      local values = { ... }
      assert.are.equal(2, numkeys)
      return eval_atomic(values[1], values[2], values[3], values[4], values[5], values[6])
    end,
    eval = function(_, _, numkeys, ...)
      local values = { ... }
      assert.are.equal(2, numkeys)
      return eval_atomic(values[1], values[2], values[3], values[4], values[5], values[6])
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

  it("charges atomically and returns allow with updated usage", function()
    local now_epoch = 1772107200 -- 2026-02-26 12:00:00 UTC
    local redis = new_fake_redis({
      store = {
        ["usage:prod:month:client:client-1:2026-02"] = "1",
        ["usage:prod:day:client:client-1:2026-02-26"] = "2",
      },
    })

    local result, meta, err = redis_store.atomic_charge_usages(redis, {
      redis_env = "prod",
      usage_grace_days = 7,
    }, "client", "client-1", 3, 10, now_epoch)

    assert.is_nil(err)
    assert.are.equal("allow", result.decision)
    assert.are.equal("within_budget", result.reason)
    assert.are.equal(1, result.month_before)
    assert.are.equal(2, result.day_before)
    assert.are.equal(4, result.month_after)
    assert.are.equal(5, result.day_after)
    assert.is_truthy(meta.script_sha)
    assert.are.equal(820800, redis.ttl_map["usage:prod:month:client:client-1:2026-02"])
    assert.are.equal(648000, redis.ttl_map["usage:prod:day:client:client-1:2026-02-26"])
  end)

  it("returns deny and does not change counters when budget is exceeded", function()
    local now_epoch = 1772107200 -- 2026-02-26 12:00:00 UTC
    local redis = new_fake_redis({
      store = {
        ["usage:prod:month:client:client-1:2026-02"] = "9",
        ["usage:prod:day:client:client-1:2026-02-26"] = "1",
      },
    })

    local result, _, err = redis_store.atomic_charge_usages(redis, {
      redis_env = "prod",
      usage_grace_days = 7,
    }, "client", "client-1", 2, 10, now_epoch)

    assert.is_nil(err)
    assert.are.equal("deny", result.decision)
    assert.are.equal("budget_exceeded", result.reason)
    assert.are.equal(9, result.month_before)
    assert.are.equal(1, result.day_before)
    assert.are.equal(9, result.month_after)
    assert.are.equal(1, result.day_after)
    assert.are.equal("9", redis.store["usage:prod:month:client:client-1:2026-02"])
    assert.are.equal("1", redis.store["usage:prod:day:client:client-1:2026-02-26"])
  end)

  it("reloads script when evalsha returns NOSCRIPT", function()
    local now_epoch = 1772107200 -- 2026-02-26 12:00:00 UTC
    local redis = new_fake_redis({
      noscript_once = true,
    })
    local conf = {
      redis_env = "prod",
      usage_grace_days = 7,
      __atomic_charge_sha = "stale-sha",
    }

    local result, meta, err = redis_store.atomic_charge_usages(redis, conf, "client", "client-1", 1, 5, now_epoch)

    assert.is_nil(err)
    assert.are.equal("allow", result.decision)
    assert.is_truthy(meta.script_sha)
    assert.are_not.equal("stale-sha", meta.script_sha)
  end)

  it("keeps accurate cutoff point under 1000 charge attempts", function()
    local now_epoch = 1772107200 -- 2026-02-26 12:00:00 UTC
    local redis = new_fake_redis({})
    local conf = {
      redis_env = "prod",
      usage_grace_days = 7,
    }
    local budget = 300
    local allow_count = 0
    local deny_count = 0

    for _ = 1, 1000 do
      local result, _, err = redis_store.atomic_charge_usages(redis, conf, "client", "client-1", 1, budget, now_epoch)
      assert.is_nil(err)
      if result.decision == "allow" then
        allow_count = allow_count + 1
      else
        deny_count = deny_count + 1
      end
    end

    assert.are.equal(300, allow_count)
    assert.are.equal(700, deny_count)
    assert.are.equal("300", redis.store["usage:prod:month:client:client-1:2026-02"])
    assert.are.equal("300", redis.store["usage:prod:day:client:client-1:2026-02-26"])
  end)
end)
