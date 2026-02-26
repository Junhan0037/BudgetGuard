-- 13.4 단계에서 핸들러가 Redis 정책/카운터를 사용하는 경로를 검증한다.
local HANDLER_MODULE = "kong.plugins.kong-cost-quota.handler"
local redis_store = require("kong.plugins.kong-cost-quota.redis_store")

local function setup_kong_env(opts)
  local options = opts or {}
  local exits = {}

  _G.kong = {
    request = {
      get_header = function()
        return nil
      end,
      get_path = function()
        return options.path or "/v1/resource"
      end,
      get_method = function()
        return options.method or "GET"
      end,
    },
    router = {
      get_route = function()
        return { id = "route-redis" }
      end,
      get_service = function()
        return { name = "svc-redis" }
      end,
    },
    response = {
      exit = function(status, body)
        exits[#exits + 1] = { status = status, body = body }
        return { status = status, body = body }
      end,
    },
    client = {
      get_consumer = function()
        return nil
      end,
      tls = {},
    },
    ctx = {
      shared = options.shared or {},
    },
    log = {
      notice = function()
        return
      end,
    },
  }

  _G.ngx = {
    var = {},
  }

  return {
    exits = exits,
  }
end

local function teardown_kong_env()
  _G.kong = nil
  _G.ngx = nil
end

local function new_fake_redis(initial)
  local store = initial and initial.store or {}
  local ttl_map = initial and initial.ttl_map or {}

  return {
    store = store,
    ttl_map = ttl_map,
    get = function(_, key)
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

describe("handler redis path", function()
  local handler

  before_each(function()
    package.loaded[HANDLER_MODULE] = nil
    handler = require(HANDLER_MODULE)
  end)

  after_each(function()
    teardown_kong_env()
  end)

  it("loads policy from redis and increases month/day usage", function()
    local now_epoch = 1772107200 -- 2026-02-26 12:00:00 UTC
    local redis = new_fake_redis({
      store = {
        ["policy:prod:client:client-1"] = [[{"version":"redis-v1","deny_status_code":429,"default":{"base_weight":2,"plan_multiplier":1,"time_multiplier":1,"custom_multiplier":1,"budget":100},"rules":{},"plan_multipliers":{}}]],
      },
    })

    setup_kong_env({
      shared = {
        jwt_claims = {
          client_id = "client-1",
        },
      },
    })

    handler:access({
      redis_host = "127.0.0.1",
      redis_env = "prod",
      usage_grace_days = 7,
      redis_now_epoch = now_epoch,
      redis_client_factory = function()
        return redis
      end,
    })

    local runtime_ctx = kong.ctx.shared.cost_quota_ctx
    assert.is_table(runtime_ctx)
    assert.are.equal("allow", runtime_ctx.decision)
    assert.are.equal("redis", runtime_ctx.policy_source)
    assert.are.equal("policy:prod:client:client-1", runtime_ctx.policy_key)
    assert.are.equal("client", runtime_ctx.usage_scope)
    assert.are.equal("client-1", runtime_ctx.usage_id)

    local month_key = runtime_ctx.usage_keys.month
    local day_key = runtime_ctx.usage_keys.day
    assert.is_truthy(month_key)
    assert.is_truthy(day_key)
    assert.are.equal("2", redis.store[month_key])
    assert.are.equal("2", redis.store[day_key])
  end)

  it("falls back to org policy when client policy is missing", function()
    local now_epoch = 1772107200 -- 2026-02-26 12:00:00 UTC
    local redis = new_fake_redis({
      store = {
        ["policy:prod:org:org-1"] = [[{"version":"org-v1","deny_status_code":429,"default":{"base_weight":1,"plan_multiplier":1,"time_multiplier":1,"custom_multiplier":1,"budget":100},"rules":{},"plan_multipliers":{}}]],
      },
    })

    setup_kong_env({
      shared = {
        jwt_claims = {
          client_id = "client-1",
          org_id = "org-1",
        },
      },
    })

    handler:access({
      redis_host = "127.0.0.1",
      redis_env = "prod",
      usage_grace_days = 7,
      redis_now_epoch = now_epoch,
      redis_client_factory = function()
        return redis
      end,
    })

    local runtime_ctx = kong.ctx.shared.cost_quota_ctx
    assert.is_table(runtime_ctx)
    assert.are.equal("policy:prod:org:org-1", runtime_ctx.policy_key)
    assert.are.equal("org", runtime_ctx.usage_scope)
    assert.are.equal("org-1", runtime_ctx.usage_id)
  end)

  it("denies when redis policy is required but missing", function()
    local env = setup_kong_env({
      shared = {
        jwt_claims = {
          client_id = "client-1",
        },
      },
    })
    local redis = new_fake_redis({})

    local result = handler:access({
      redis_host = "127.0.0.1",
      redis_env = "prod",
      redis_policy_required = true,
      redis_client_factory = function()
        return redis
      end,
    })

    assert.are.equal(1, #env.exits)
    assert.are.equal(429, env.exits[1].status)
    assert.are.equal("policy_missing", env.exits[1].body.reason)
    assert.are.equal(429, result.status)
  end)

  it("uses max(month, day) usage for decision and skips increment on deny", function()
    local now_epoch = 1772107200 -- 2026-02-26 12:00:00 UTC
    local identity = {
      client_id = "client-1",
    }
    local month_bucket = redis_store.compute_bucket("month", now_epoch)
    local day_bucket = redis_store.compute_bucket("day", now_epoch)
    local month_key = redis_store.build_usage_key("prod", "month", "client", "client-1", month_bucket)
    local day_key = redis_store.build_usage_key("prod", "day", "client", "client-1", day_bucket)

    local redis = new_fake_redis({
      store = {
        ["policy:prod:client:client-1"] = [[{"version":"redis-v1","deny_status_code":429,"default":{"base_weight":2,"plan_multiplier":1,"time_multiplier":1,"custom_multiplier":1,"budget":10},"rules":{},"plan_multipliers":{}}]],
        [month_key] = "9",
        [day_key] = "1",
      },
    })

    local env = setup_kong_env({
      shared = {
        jwt_claims = identity,
      },
    })

    handler:access({
      redis_host = "127.0.0.1",
      redis_env = "prod",
      usage_grace_days = 7,
      redis_now_epoch = now_epoch,
      redis_client_factory = function()
        return redis
      end,
    })

    assert.are.equal(1, #env.exits)
    assert.are.equal(429, env.exits[1].status)
    assert.are.equal("budget_exceeded", env.exits[1].body.reason)
    assert.are.equal("9", redis.store[month_key])
    assert.are.equal("1", redis.store[day_key])
  end)
end)
