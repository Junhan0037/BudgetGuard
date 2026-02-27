-- 13.9 Load 테스트용 경량 하네스.
-- 캐시 적중률과 p95 지연을 회귀 관점에서 검증한다.
local redis_store = require("kong.plugins.kong-cost-quota.redis_store")
local policy_cache = require("kong.plugins.kong-cost-quota.policy_cache")

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
    delete = function(_, key)
      data[key] = nil
      return true
    end,
  }
end

-- p95 계산을 위해 샘플 배열을 정렬해 percentile 값을 구한다.
local function percentile(samples, p)
  local cloned = {}
  for index = 1, #samples do
    cloned[index] = samples[index]
  end
  table.sort(cloned)

  local target_index = math.ceil(#cloned * p)
  if target_index < 1 then
    target_index = 1
  end
  if target_index > #cloned then
    target_index = #cloned
  end

  return cloned[target_index]
end

describe("load harness", function()
  before_each(function()
    policy_cache._reset_for_test()
    _G.ngx = nil
  end)

  after_each(function()
    _G.ngx = nil
  end)

  it("keeps cache hit ratio >= 90% and p95 latency under 2ms", function()
    local now_value = 1772107200
    local shared = new_fake_shared_dict(function()
      return now_value
    end)

    _G.ngx = {
      shared = {
        kong_cost_quota_cache = shared,
      },
      now = function()
        return now_value
      end,
    }

    local policy_key = "policy:prod:client:client-load"
    local raw_policy = [[{"version":"load-v1","default":{"base_weight":1,"plan_multiplier":1,"time_multiplier":1,"custom_multiplier":1,"budget":1000},"rules":{},"plan_multipliers":{}}]]
    local redis_get_calls = 0
    local redis = {
      get = function(_, key)
        redis_get_calls = redis_get_calls + 1
        if key == policy_key then
          return raw_policy, nil
        end
        return nil, nil
      end,
    }

    local conf = {
      redis_env = "prod",
      policy_cache_enabled = true,
      policy_cache_ttl_sec = 60,
      policy_cache_shm = "kong_cost_quota_cache",
      policy_cache_version_probe_sec = 30,
      policy_cache_now_epoch = now_value,
    }
    local identity = {
      client_id = "client-load",
    }

    local iterations = 5000
    local cache_hit_count = 0
    local latencies_ms = {}

    for index = 1, iterations do
      local start_time = os.clock()
      local policy, meta, err = redis_store.fetch_policy_with_cache(redis, conf, identity)
      local elapsed_ms = (os.clock() - start_time) * 1000

      assert.is_nil(err)
      assert.is_table(policy)
      assert.is_table(meta)
      if meta.cache_hit then
        cache_hit_count = cache_hit_count + 1
      end
      latencies_ms[index] = elapsed_ms
    end

    local hit_ratio = cache_hit_count / iterations
    local p95_latency_ms = percentile(latencies_ms, 0.95)

    assert.is_true(
      hit_ratio >= 0.9,
      string.format("cache hit ratio must be >= 0.9, got %.4f (redis_get_calls=%d)", hit_ratio, redis_get_calls)
    )
    assert.is_true(
      p95_latency_ms < 2,
      string.format("p95 latency must be < 2ms, got %.6fms", p95_latency_ms)
    )
  end)
end)
