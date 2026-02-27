-- 13.3 단계 핸들러(access/log) 동작 검증 테스트.
local HANDLER_MODULE = "kong.plugins.kong-cost-quota.handler"

-- 테스트마다 최소 Kong 런타임 환경을 구성한다.
local function setup_kong_env(opts)
  local options = opts or {}
  local exits = {}
  local logs = {}
  local response_headers = {}

  local headers = options.headers or {}
  local path = options.path or "/v1/resource"
  local method = options.method or "GET"
  local route = options.route or { id = "route-1" }
  local service = options.service or { name = "svc-main" }
  local consumer = options.consumer
  local shared = options.shared or {}

  _G.kong = {
    request = {
      get_header = function(name)
        return headers[name]
      end,
      get_path = function()
        return path
      end,
      get_method = function()
        return method
      end,
    },
    router = {
      get_route = function()
        return route
      end,
      get_service = function()
        return service
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
        return consumer
      end,
      tls = options.tls or {},
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
    var = options.ngx_var or {},
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

local function build_base_policy(overrides)
  local policy = {
    version = "v2026-02-26",
    deny_status_code = 429,
    default = {
      base_weight = 2,
      plan_multiplier = 1.0,
      time_multiplier = 1.0,
      custom_multiplier = 1.0,
      budget = 10,
    },
    rules = {},
    plan_multipliers = {},
  }

  if type(overrides) == "table" then
    for key, value in pairs(overrides) do
      policy[key] = value
    end
  end

  return policy
end

describe("handler", function()
  local handler

  before_each(function()
    package.loaded[HANDLER_MODULE] = nil
    handler = require(HANDLER_MODULE)
  end)

  after_each(function()
    teardown_kong_env()
  end)

  it("prioritizes JWT claims over mTLS, consumer, and headers", function()
    local env = setup_kong_env({
      headers = {
        ["x-client-id"] = "header-client",
        ["x-org-id"] = "header-org",
        ["x-plan"] = "header-plan",
      },
      shared = {
        authenticated_jwt_token = {
          claims = {
            client_id = "jwt-client",
            org_id = "jwt-org",
            plan = "enterprise",
          },
        },
      },
      consumer = { id = "consumer-client" },
      ngx_var = {
        ssl_client_serial = "mtls-serial",
      },
    })

    handler:access({
      allow_trusted_identity_headers = true,
      policy = build_base_policy(),
    })

    assert.are.equal(0, #env.exits)
    local runtime_ctx = kong.ctx.shared.cost_quota_ctx
    assert.is_table(runtime_ctx)
    assert.are.equal("jwt-client", runtime_ctx.identity.client_id)
    assert.are.equal("jwt-org", runtime_ctx.identity.org_id)
    assert.are.equal("enterprise", runtime_ctx.identity.plan)
    assert.are.equal("jwt_claims", runtime_ctx.identity_source.client_id)
  end)

  it("uses mTLS serial as identity when JWT is absent", function()
    setup_kong_env({
      ngx_var = {
        ssl_client_serial = "mtls-client-001",
      },
    })

    handler:access({
      policy = build_base_policy(),
    })

    local runtime_ctx = kong.ctx.shared.cost_quota_ctx
    assert.is_table(runtime_ctx)
    assert.are.equal("mtls-client-001", runtime_ctx.identity.client_id)
    assert.are.equal("mtls", runtime_ctx.identity_source.client_id)
  end)

  it("uses consumer id when JWT and mTLS are absent", function()
    setup_kong_env({
      consumer = { id = "consumer-123" },
    })

    handler:access({
      policy = build_base_policy(),
    })

    local runtime_ctx = kong.ctx.shared.cost_quota_ctx
    assert.is_table(runtime_ctx)
    assert.are.equal("consumer-123", runtime_ctx.identity.client_id)
    assert.are.equal("api_key_consumer", runtime_ctx.identity_source.client_id)
  end)

  it("blocks header identity when trusted header mode is disabled", function()
    local env = setup_kong_env({
      headers = {
        ["x-client-id"] = "header-client",
      },
    })

    local result = handler:access({
      allow_trusted_identity_headers = false,
      policy = build_base_policy(),
    })

    assert.are.equal(1, #env.exits)
    assert.are.equal(429, env.exits[1].status)
    assert.are.equal("identity_missing", env.exits[1].body.reason)
    assert.are.equal(429, result.status)
  end)

  it("allows header identity when trusted header mode is enabled", function()
    setup_kong_env({
      headers = {
        ["x-client-id"] = "header-client",
        ["x-org-id"] = "header-org",
        ["x-plan"] = "pro",
      },
    })

    handler:access({
      allow_trusted_identity_headers = true,
      policy = build_base_policy(),
    })

    local runtime_ctx = kong.ctx.shared.cost_quota_ctx
    assert.is_table(runtime_ctx)
    assert.are.equal("header-client", runtime_ctx.identity.client_id)
    assert.are.equal("header-org", runtime_ctx.identity.org_id)
    assert.are.equal("trusted_header", runtime_ctx.identity_source.client_id)
  end)

  it("sets observability headers and emits metrics on allow request", function()
    local env = setup_kong_env({
      shared = {
        jwt_claims = {
          client_id = "header-check-client",
        },
      },
    })

    handler:access({
      policy = build_base_policy(),
    })

    assert.are.equal("2", env.response_headers["X-Usage-Units"])
    assert.are.equal("8", env.response_headers["X-Remaining-Units"])
    assert.are.equal("day", env.response_headers["X-Budget-Window"])
    assert.are.equal("v2026-02-26", env.response_headers["X-Policy-Version"])
    assert.are.equal("default", env.response_headers["X-Policy-Source"])
    assert.is_nil(env.response_headers["Retry-After"])

    assert.is_truthy(find_log(env.logs, "cost_quota_metric"))
    assert.is_truthy(find_log_with_keywords(env.logs, "cost_quota.requests", "default"))
    assert.is_truthy(find_log(env.logs, "cost_quota.units_charged"))
    assert.is_truthy(find_log(env.logs, "cost_quota.redis_latency_ms"))
    assert.is_truthy(find_log(env.logs, "cost_quota.policy_cache_hit"))
  end)

  it("denies when projected usage exceeds budget", function()
    local env = setup_kong_env({
      shared = {
        jwt_claims = {
          client_id = "jwt-client",
        },
      },
    })

    local result = handler:access({
      policy = build_base_policy({
        default = {
          base_weight = 3,
          plan_multiplier = 1.0,
          time_multiplier = 1.0,
          custom_multiplier = 1.0,
          budget = 2,
        },
      }),
    })

    assert.are.equal(1, #env.exits)
    assert.are.equal(429, env.exits[1].status)
    assert.are.equal("budget_exceeded", env.exits[1].body.reason)
    assert.are.equal(429, result.status)

    local runtime_ctx = kong.ctx.shared.cost_quota_ctx
    assert.are.equal("deny", runtime_ctx.decision)
    assert.are.equal("budget_exceeded", runtime_ctx.reason)
    assert.are.equal("3", env.response_headers["X-Usage-Units"])
    assert.are.equal("0", env.response_headers["X-Remaining-Units"])
    assert.are.equal("day", env.response_headers["X-Budget-Window"])
    assert.are.equal("default", env.response_headers["X-Policy-Source"])
    assert.is_nil(env.response_headers["Retry-After"])
  end)

  it("uses policy deny status code when deny response is returned", function()
    local env = setup_kong_env({
      shared = {
        authenticated_claims = {
          client_id = "claim-client",
        },
      },
    })

    handler:access({
      policy = build_base_policy({
        deny_status_code = 402,
        default = {
          base_weight = 5,
          plan_multiplier = 1.0,
          time_multiplier = 1.0,
          custom_multiplier = 1.0,
          budget = 1,
        },
      }),
    })

    assert.are.equal(1, #env.exits)
    assert.are.equal(402, env.exits[1].status)
  end)

  it("writes structured audit log in log phase", function()
    local env = setup_kong_env({
      shared = {
        jwt_claims = {
          client_id = "audit-client",
          org_id = "audit-org",
        },
      },
    })

    local conf = {
      audit_log_enabled = true,
      policy = build_base_policy(),
    }

    handler:access(conf)
    handler:log(conf)

    local audit_log = find_log(env.logs, "cost_quota_audit")
    assert.is_truthy(audit_log)
    assert.is_truthy(string.find(audit_log, "audit-client", 1, true))
    assert.is_truthy(string.find(audit_log, "audit-org", 1, true))
    assert.is_truthy(string.find(audit_log, "route_id", 1, true))
    assert.is_truthy(string.find(audit_log, "units", 1, true))
    assert.is_truthy(string.find(audit_log, "remaining", 1, true))
    assert.is_truthy(string.find(audit_log, "policy_version", 1, true))
    assert.is_truthy(string.find(audit_log, "decision", 1, true))
    assert.is_truthy(string.find(audit_log, "reason", 1, true))
  end)

  it("skips audit log when audit_log_enabled is false", function()
    local env = setup_kong_env({
      shared = {
        jwt_claims = {
          client_id = "no-log-client",
        },
      },
    })

    local conf = {
      audit_log_enabled = false,
      policy = build_base_policy(),
    }

    handler:access(conf)
    handler:log(conf)

    assert.is_nil(find_log(env.logs, "cost_quota_audit"))
  end)
end)
