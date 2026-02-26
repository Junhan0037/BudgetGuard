-- 13.6 정책 캐시(L1/L2/TTL/version probe) 검증 테스트.
local MODULE_NAME = "kong.plugins.kong-cost-quota.policy_cache"

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

describe("policy_cache", function()
  local policy_cache
  local now_value
  local shared_dict

  before_each(function()
    now_value = 1000
    shared_dict = new_fake_shared_dict(function()
      return now_value
    end)

    _G.ngx = {
      shared = {
        kong_cost_quota_cache = shared_dict,
      },
      now = function()
        return now_value
      end,
    }

    package.loaded[MODULE_NAME] = nil
    policy_cache = require(MODULE_NAME)
    policy_cache._reset_for_test()
  end)

  after_each(function()
    _G.ngx = nil
  end)

  it("resolves normal and emergency ttl range", function()
    local normal_ttl = policy_cache.resolve_policy_ttl({
      emergency_mode = false,
      policy_cache_ttl_sec = 70,
    })
    local emergency_ttl = policy_cache.resolve_policy_ttl({
      emergency_mode = true,
      policy_cache_ttl_emergency_sec = 6,
    })

    assert.are.equal(70, normal_ttl)
    assert.are.equal(6, emergency_ttl)
  end)

  it("returns cache_l1 on repeated read after set", function()
    local conf = {
      policy_cache_enabled = true,
      policy_cache_ttl_sec = 60,
      policy_cache_shm = "kong_cost_quota_cache",
      policy_cache_l1_size = 128,
    }
    local key = "policy:prod:client:client-1"

    local ok, err = policy_cache.set_policy(conf, key, {
      raw_policy = [[{"version":"v1"}]],
      policy_version = "v1",
    })
    assert.is_true(ok)
    assert.is_nil(err)

    local entry, source = policy_cache.get_policy(conf, key)
    assert.is_table(entry)
    assert.are.equal("cache_l1", source)
    assert.are.equal("v1", entry.policy_version)
  end)

  it("reads from cache_l2 when l1 is cold", function()
    local conf = {
      policy_cache_enabled = true,
      policy_cache_ttl_sec = 60,
      policy_cache_shm = "kong_cost_quota_cache",
    }
    local key = "policy:prod:org:org-1"

    local ok = policy_cache.set_policy(conf, key, {
      raw_policy = [[{"version":"v1"}]],
      policy_version = "v1",
    })
    assert.is_true(ok)

    -- 모듈을 다시 로드해 L1을 비우고 L2로부터 재조회한다.
    package.loaded[MODULE_NAME] = nil
    local reloaded = require(MODULE_NAME)
    reloaded._reset_for_test()

    local entry, source = reloaded.get_policy(conf, key)
    assert.is_table(entry)
    assert.are.equal("cache_l2", source)
    assert.are.equal("v1", entry.policy_version)
  end)

  it("supports version probe marker with short ttl", function()
    local conf = {
      policy_cache_enabled = true,
      policy_cache_version_probe_sec = 5,
      policy_cache_now_epoch = now_value,
      policy_cache_shm = "kong_cost_quota_cache",
    }
    local key = "policy:prod:client:client-2"

    local need_probe_1 = policy_cache.should_probe_version(conf, key)
    assert.is_true(need_probe_1)

    policy_cache.mark_probed(conf, key)
    local need_probe_2 = policy_cache.should_probe_version(conf, key)
    assert.is_false(need_probe_2)

    now_value = now_value + 6
    conf.policy_cache_now_epoch = now_value
    local need_probe_3 = policy_cache.should_probe_version(conf, key)
    assert.is_true(need_probe_3)
  end)
end)
