-- 비용 쿼터 플러그인 스키마.
-- 게이트웨이 설정 검증 규칙을 정의한다.
local typedefs = require("kong.db.schema.typedefs")

return {
  name = "kong-cost-quota",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          {
            deny_status_code = {
              type = "integer",
              required = false,
              default = 429,
              one_of = { 402, 429 },
            },
          },
          {
            policy_validation_mode = {
              type = "string",
              required = false,
              default = "strict_with_safe_defaults",
              one_of = { "strict_with_safe_defaults" },
            },
          },
          {
            default_plan_multiplier = {
              type = "number",
              required = false,
              default = 1.0,
              between = { 0, math.huge },
            },
          },
          {
            default_time_multiplier = {
              type = "number",
              required = false,
              default = 1.0,
              between = { 0, math.huge },
            },
          },
          {
            default_custom_multiplier = {
              type = "number",
              required = false,
              default = 1.0,
              between = { 0, math.huge },
            },
          },
          {
            allow_trusted_identity_headers = {
              type = "boolean",
              required = false,
              default = false,
            },
          },
          {
            rollout_mode = {
              type = "string",
              required = false,
              default = "enforce",
              one_of = { "shadow", "partial", "enforce" },
            },
          },
          {
            partial_enforce_route_ids = {
              type = "array",
              required = false,
              default = {},
              elements = {
                type = "string",
              },
            },
          },
          {
            partial_enforce_service_names = {
              type = "array",
              required = false,
              default = {},
              elements = {
                type = "string",
              },
            },
          },
          {
            partial_enforce_client_ids = {
              type = "array",
              required = false,
              default = {},
              elements = {
                type = "string",
              },
            },
          },
          {
            emergency_target_client_ids = {
              type = "array",
              required = false,
              default = {},
              elements = {
                type = "string",
              },
            },
          },
          {
            emergency_action = {
              type = "string",
              required = false,
              default = "none",
              one_of = { "none", "tighten", "relax" },
            },
          },
          {
            emergency_multiplier = {
              type = "number",
              required = false,
              default = 1.0,
              between = { 0, math.huge },
            },
          },
          {
            emergency_cache_ttl_sec = {
              type = "integer",
              required = false,
              default = 5,
              between = { 5, 10 },
            },
          },
          {
            audit_log_enabled = {
              type = "boolean",
              required = false,
              default = true,
            },
          },
          {
            redis_host = {
              type = "string",
              required = false,
              default = "127.0.0.1",
            },
          },
          {
            redis_port = {
              type = "integer",
              required = false,
              default = 6379,
              between = { 1, 65535 },
            },
          },
          {
            redis_database = {
              type = "integer",
              required = false,
              default = 0,
              between = { 0, 15 },
            },
          },
          {
            redis_password = {
              type = "string",
              required = false,
            },
          },
          {
            redis_timeout_ms = {
              type = "integer",
              required = false,
              default = 20,
              between = { 5, 20 },
            },
          },
          {
            failure_strategy = {
              type = "string",
              required = false,
              default = "fail_open",
              one_of = { "fail_open", "fail_closed" },
            },
          },
          {
            failure_deny_status = {
              type = "integer",
              required = false,
              default = 503,
              one_of = { 429, 503 },
            },
          },
          {
            redis_env = {
              type = "string",
              required = false,
              default = "prod",
            },
          },
          {
            usage_grace_days = {
              type = "integer",
              required = false,
              default = 7,
              between = { 0, 3650 },
            },
          },
          {
            redis_policy_required = {
              type = "boolean",
              required = false,
              default = false,
            },
          },
          {
            redis_atomic_enabled = {
              type = "boolean",
              required = false,
              default = true,
            },
          },
          {
            policy_cache_enabled = {
              type = "boolean",
              required = false,
              default = true,
            },
          },
          {
            policy_cache_ttl_sec = {
              type = "integer",
              required = false,
              default = 60,
              between = { 30, 120 },
            },
          },
          {
            emergency_mode = {
              type = "boolean",
              required = false,
              default = false,
            },
          },
          {
            policy_cache_ttl_emergency_sec = {
              type = "integer",
              required = false,
              default = 5,
              between = { 5, 10 },
            },
          },
          {
            policy_cache_shm = {
              type = "string",
              required = false,
              default = "kong_cost_quota_cache",
            },
          },
          {
            policy_cache_l1_size = {
              type = "integer",
              required = false,
              default = 1024,
              between = { 64, 65535 },
            },
          },
          {
            policy_cache_version_probe_sec = {
              type = "integer",
              required = false,
              default = 5,
              between = { 1, 30 },
            },
          },
          {
            circuit_breaker_enabled = {
              type = "boolean",
              required = false,
              default = true,
            },
          },
          {
            circuit_failure_window_sec = {
              type = "integer",
              required = false,
              default = 30,
              between = { 5, 300 },
            },
          },
          {
            circuit_min_requests = {
              type = "integer",
              required = false,
              default = 20,
              between = { 1, 100000 },
            },
          },
          {
            circuit_failure_threshold = {
              type = "number",
              required = false,
              default = 0.5,
              between = { 0, 1 },
            },
          },
          {
            circuit_open_sec = {
              type = "integer",
              required = false,
              default = 15,
              between = { 1, 300 },
            },
          },
          {
            redis_circuit_shm = {
              type = "string",
              required = false,
              default = "kong_cost_quota_circuit",
            },
          },
        },
      },
    },
  },
}
