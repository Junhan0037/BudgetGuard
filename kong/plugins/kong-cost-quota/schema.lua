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
              between = { 1, 60000 },
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
        },
      },
    },
  },
}
