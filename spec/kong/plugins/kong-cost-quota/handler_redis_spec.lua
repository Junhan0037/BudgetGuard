-- 13.4 단계에서 핸들러가 Redis 정책/카운터를 사용하는 경로를 검증한다.
local HANDLER_MODULE = "kong.plugins.kong-cost-quota.handler"
local redis_store = require("kong.plugins.kong-cost-quota.redis_store")
local policy_cache = require("kong.plugins.kong-cost-quota.policy_cache")
local failure_control = require("kong.plugins.kong-cost-quota.failure_control")

local function new_fake_shared_dict(now_ref)
  local data = {}

  local function expired(item)
    if not item or not item.expires_at then
      return false
    end
    return now_ref() >= item.expires_at
  end

  return {
    get = function(_, key)
      local item = data[key]
      if expired(item) then
        data[key] = nil
        return nil
      end
      return item and item.value or nil
    end,
    set = function(_, key, value, ttl)
      local expires_at = nil
      if ttl and ttl > 0 then
        expires_at = now_ref() + ttl
      end
      data[key] = {
        value = value,
        expires_at = expires_at,
      }
      return true, nil
    end,
    incr = function(_, key, value)
      local item = data[key]
      if expired(item) then
        data[key] = nil
        item = nil
      end

      if not item then
        return nil, "not found"
      end

      local current = tonumber(item.value) or 0
      local next_value = current + value
      item.value = next_value
      return next_value, nil
    end,
    delete = function(_, key)
      data[key] = nil
      return true
    end,
  }
end

local function setup_kong_env(opts)
  local options = opts or {}
  local exits = {}
  local logs = {}
  local response_headers = {}
  local shared = options.shared or {}
  local now_value = options.now_epoch or 0
  local shared_dicts = options.shared_dicts or {}

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
      set_header = function(name, value)
        response_headers[name] = tostring(value)
      end,
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
      shared = shared,
    },
    log = {
      notice = function(message)
        logs[#logs + 1] = message
      end,
    },
  }

  _G.ngx = {
    var = {},
    shared = shared_dicts,
    now = function()
      return now_value
    end,
  }

  return {
    exits = exits,
    logs = logs,
    response_headers = response_headers,
  }
end

local function find_log(logs, keyword)
  -- 로그 배열에서 특정 문자열이 포함된 첫 메시지를 찾는다.
  for _, message in ipairs(logs or {}) do
    if string.find(message, keyword, 1, true) then
      return message
    end
  end
  return nil
end

local function find_log_with_keywords(logs, keyword1, keyword2)
  -- 메트릭 이름/태그처럼 두 키워드가 함께 있는 로그를 찾는다.
  for _, message in ipairs(logs or {}) do
    if string.find(message, keyword1, 1, true) and string.find(message, keyword2, 1, true) then
      return message
    end
  end
  return nil
end

local function teardown_kong_env()
  _G.kong = nil
  _G.ngx = nil
end

local function new_fake_redis(initial)
  local store = initial and initial.store or {}
  local ttl_map = initial and initial.ttl_map or {}
  local scripts = {}
  local script_sequence = 0
  local force_eval_error = initial and initial.force_eval_error

  local function eval_atomic(month_key, day_key, units, budget_arg, month_ttl, day_ttl)
    local charge_units = tonumber(units) or 0
    local month_before = tonumber(store[month_key]) or 0
    local day_before = tonumber(store[day_key]) or 0
    local current_before = math.max(month_before, day_before)
    local projected_usage = math.max(month_before + charge_units, day_before + charge_units)

    if force_eval_error then
      return nil, force_eval_error
    end

    if budget_arg ~= nil and budget_arg ~= "" then
      local budget = tonumber(budget_arg)
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

describe("handler redis path", function()
  local handler

  before_each(function()
    policy_cache._reset_for_test()
    failure_control._reset_for_test()
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

    local env = setup_kong_env({
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
    assert.is_true(runtime_ctx.atomic)
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
    assert.are.equal("redis", env.response_headers["X-Policy-Source"])
    assert.are.equal("day", env.response_headers["X-Budget-Window"])
    assert.is_truthy(find_log(env.logs, "cost_quota.requests"))
    assert.is_truthy(find_log(env.logs, "cost_quota.units_charged"))
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
    assert.is_true(runtime_ctx.atomic)
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
    assert.are.equal("redis", env.response_headers["X-Policy-Source"])
    assert.are.equal("day", env.response_headers["X-Budget-Window"])
    assert.is_not_nil(env.response_headers["Retry-After"])
    assert.is_truthy(find_log(env.logs, "cost_quota.requests"))
  end)

  it("fails open when atomic script execution fails", function()
    local now_epoch = 1772107200 -- 2026-02-26 12:00:00 UTC
    local redis = new_fake_redis({
      store = {
        ["policy:prod:client:client-1"] = [[{"version":"redis-v1","deny_status_code":429,"default":{"base_weight":2,"plan_multiplier":1,"time_multiplier":1,"custom_multiplier":1,"budget":10},"rules":{},"plan_multipliers":{}}]],
      },
      force_eval_error = "ERR simulated script failure",
    })

    local env = setup_kong_env({
      shared = {
        jwt_claims = {
          client_id = "client-1",
        },
      },
    })

    local result = handler:access({
      redis_host = "127.0.0.1",
      redis_env = "prod",
      usage_grace_days = 7,
      redis_now_epoch = now_epoch,
      redis_client_factory = function()
        return redis
      end,
    })

    assert.are.equal(0, #env.exits)
    assert.is_nil(result)
    local runtime_ctx = kong.ctx.shared.cost_quota_ctx
    assert.are.equal("allow", runtime_ctx.decision)
    assert.are.equal("atomic_charge_failed_fail_open", runtime_ctx.reason)
    assert.is_true(runtime_ctx.atomic)
    assert.is_truthy(runtime_ctx.atomic_error)
  end)

  it("fails closed when redis connection fails", function()
    local env = setup_kong_env({
      shared = {
        jwt_claims = {
          client_id = "client-1",
        },
      },
    })

    local result = handler:access({
      redis_host = "127.0.0.1",
      redis_env = "prod",
      failure_strategy = "fail_closed",
      failure_deny_status = 503,
      redis_client_factory = function()
        return nil, "timeout"
      end,
    })

    assert.are.equal(1, #env.exits)
    assert.are.equal(503, env.exits[1].status)
    assert.are.equal(503, result.status)
    assert.is_truthy(env.exits[1].body.reason:find("redis_connect_failed_fail_closed", 1, true))
    assert.are.equal("deny", kong.ctx.shared.cost_quota_ctx.decision)
  end)

  it("keeps fail-open default when redis connection fails", function()
    local env = setup_kong_env({
      shared = {
        jwt_claims = {
          client_id = "client-1",
        },
      },
    })

    local result = handler:access({
      redis_host = "127.0.0.1",
      redis_env = "prod",
      redis_client_factory = function()
        return nil, "timeout"
      end,
    })

    assert.are.equal(0, #env.exits)
    assert.is_nil(result)
    assert.are.equal("allow", kong.ctx.shared.cost_quota_ctx.decision)
    assert.is_truthy(kong.ctx.shared.cost_quota_ctx.reason:find("redis_connect_failed_fail_open", 1, true))
  end)

  it("fails closed when atomic script execution fails under fail_closed", function()
    local now_epoch = 1772107200 -- 2026-02-26 12:00:00 UTC
    local redis = new_fake_redis({
      store = {
        ["policy:prod:client:client-1"] = [[{"version":"redis-v1","deny_status_code":429,"default":{"base_weight":2,"plan_multiplier":1,"time_multiplier":1,"custom_multiplier":1,"budget":10},"rules":{},"plan_multipliers":{}}]],
      },
      force_eval_error = "ERR simulated script failure",
    })

    local env = setup_kong_env({
      shared = {
        jwt_claims = {
          client_id = "client-1",
        },
      },
    })

    local result = handler:access({
      redis_host = "127.0.0.1",
      redis_env = "prod",
      usage_grace_days = 7,
      redis_now_epoch = now_epoch,
      failure_strategy = "fail_closed",
      failure_deny_status = 503,
      redis_client_factory = function()
        return redis
      end,
    })

    assert.are.equal(1, #env.exits)
    assert.are.equal(503, env.exits[1].status)
    assert.are.equal(503, result.status)
    assert.is_truthy(env.exits[1].body.reason:find("atomic_charge_failed_fail_closed", 1, true))
    assert.are.equal("deny", kong.ctx.shared.cost_quota_ctx.decision)
  end)

  it("opens circuit breaker after threshold and skips redis connection", function()
    local now_epoch = 1772107200 -- 2026-02-26 12:00:00 UTC
    local circuit_dict = new_fake_shared_dict(function()
      return now_epoch
    end)
    local connect_calls = 0

    setup_kong_env({
      shared = {
        jwt_claims = {
          client_id = "client-circuit",
        },
      },
      shared_dicts = {
        kong_cost_quota_circuit = circuit_dict,
      },
    })

    local conf = {
      redis_host = "127.0.0.1",
      redis_env = "prod",
      redis_now_epoch = now_epoch,
      circuit_breaker_enabled = true,
      circuit_failure_window_sec = 30,
      circuit_min_requests = 1,
      circuit_failure_threshold = 1.0,
      circuit_open_sec = 60,
      redis_circuit_shm = "kong_cost_quota_circuit",
      redis_client_factory = function()
        connect_calls = connect_calls + 1
        return nil, "connection refused"
      end,
    }

    handler:access(conf)
    assert.are.equal(1, connect_calls)
    assert.is_truthy(kong.ctx.shared.cost_quota_ctx.reason:find("redis_connect_failed_fail_open", 1, true))

    handler:access(conf)
    assert.are.equal(1, connect_calls)
    assert.is_truthy(kong.ctx.shared.cost_quota_ctx.reason:find("redis_circuit_open_fail_open", 1, true))
    assert.is_true(kong.ctx.shared.cost_quota_ctx.redis_circuit_open)
  end)

  it("uses cache_l1 source after the first redis policy fetch", function()
    local now_epoch = 1772107200 -- 2026-02-26 12:00:00 UTC
    local cache_dict = new_fake_shared_dict(function()
      return now_epoch
    end)
    local redis = new_fake_redis({
      store = {
        ["policy:prod:client:client-cache"] = [[{"version":"cache-v1","deny_status_code":429,"default":{"base_weight":2,"plan_multiplier":1,"time_multiplier":1,"custom_multiplier":1,"budget":100},"rules":{},"plan_multipliers":{}}]],
      },
    })

    local env = setup_kong_env({
      now_epoch = now_epoch,
      shared = {
        jwt_claims = {
          client_id = "client-cache",
        },
      },
      shared_dicts = {
        kong_cost_quota_cache = cache_dict,
      },
    })

    local conf = {
      redis_host = "127.0.0.1",
      redis_env = "prod",
      usage_grace_days = 7,
      redis_now_epoch = now_epoch,
      redis_client_factory = function()
        return redis
      end,
      policy_cache_enabled = true,
      policy_cache_ttl_sec = 60,
      policy_cache_shm = "kong_cost_quota_cache",
      policy_cache_version_probe_sec = 5,
      policy_cache_now_epoch = now_epoch,
    }

    handler:access(conf)
    assert.are.equal("redis", kong.ctx.shared.cost_quota_ctx.policy_source)
    assert.are.equal("redis", env.response_headers["X-Policy-Source"])

    handler:access(conf)
    assert.are.equal("cache_l1", kong.ctx.shared.cost_quota_ctx.policy_source)
    assert.are.equal("cache", env.response_headers["X-Policy-Source"])
    local requests_metric_log = find_log_with_keywords(env.logs, "cost_quota.requests", "cache")
    assert.is_truthy(requests_metric_log)
  end)
end)
