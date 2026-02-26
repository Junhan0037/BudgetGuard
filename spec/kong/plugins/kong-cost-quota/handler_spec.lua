-- 13.3 단계 핸들러(access/log) 동작 검증 테스트.
local HANDLER_MODULE = "kong.plugins.kong-cost-quota.handler"

-- 테스트마다 최소 Kong 런타임 환경을 구성한다.
local function setup_kong_env(opts)
  local options = opts or {}
  local exits = {}
  local logs = {}

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
  }
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

    assert.are.equal(1, #env.logs)
    assert.is_truthy(string.find(env.logs[1], "cost_quota_audit", 1, true))
    assert.is_truthy(string.find(env.logs[1], "audit-client", 1, true))
    assert.is_truthy(string.find(env.logs[1], "decision", 1, true))
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

    assert.are.equal(0, #env.logs)
  end)
end)
