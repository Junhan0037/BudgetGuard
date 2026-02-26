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
        },
      },
    },
  },
}
