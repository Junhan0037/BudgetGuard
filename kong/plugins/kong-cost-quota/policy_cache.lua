-- 정책 캐시 모듈.
-- 13.6 단계에서 L1(lrucache) + L2(ngx.shared) 캐시를 통합 관리한다.
local M = {}

local has_lrucache, lrucache = pcall(require, "resty.lrucache")

local L2_DATA_PREFIX = "pc:data:"
local L2_VERSION_PREFIX = "pc:version:"
local L2_PROBE_PREFIX = "pc:probe:"

local l1_cache = nil
local l1_probe_cache = nil
local l1_cache_size = nil

local function now_epoch(conf)
  if type(conf) == "table" and type(conf.policy_cache_now_epoch) == "number" then
    return tonumber(conf.policy_cache_now_epoch)
  end

  if ngx and type(ngx.now) == "function" then
    return ngx.now()
  end

  return os.time()
end

local function to_integer(value, default_value)
  local parsed = tonumber(value)
  if not parsed then
    return default_value
  end
  return math.floor(parsed)
end

local function is_non_empty_string(value)
  return type(value) == "string" and value:match("%S") ~= nil
end

local function resolve_l1_size(conf)
  local size = type(conf) == "table" and conf.policy_cache_l1_size or nil
  size = to_integer(size, 1024)
  if size < 64 then
    size = 64
  end
  return size
end

local function resolve_probe_ttl(conf)
  local ttl = type(conf) == "table" and conf.policy_cache_version_probe_sec or nil
  ttl = to_integer(ttl, 5)
  if ttl < 1 then
    ttl = 1
  end
  if ttl > 30 then
    ttl = 30
  end
  return ttl
end

local function fallback_get(store, key, now_ts)
  local item = store[key]
  if not item then
    return nil
  end

  if item.expires_at and item.expires_at <= now_ts then
    store[key] = nil
    return nil
  end

  return item.value
end

local function fallback_set(store, key, value, ttl, now_ts)
  local expires_at = nil
  if ttl and ttl > 0 then
    expires_at = now_ts + ttl
  end

  store[key] = {
    value = value,
    expires_at = expires_at,
  }
end

local function fallback_delete(store, key)
  store[key] = nil
end

local function ensure_l1(conf)
  local size = resolve_l1_size(conf)
  if l1_cache and l1_probe_cache and l1_cache_size == size then
    return
  end

  l1_cache_size = size

  if has_lrucache then
    l1_cache = lrucache.new(size)
    l1_probe_cache = lrucache.new(size)
    return
  end

  -- 테스트/로컬 환경에서 resty.lrucache가 없을 때 사용할 단순 fallback 구현이다.
  l1_cache = { __fallback_store = {} }
  l1_probe_cache = { __fallback_store = {} }
end

local function l1_get(cache_ref, key, conf)
  if not cache_ref then
    return nil
  end

  local now_ts = now_epoch(conf)
  if cache_ref.__fallback_store then
    return fallback_get(cache_ref.__fallback_store, key, now_ts)
  end

  return cache_ref:get(key)
end

local function l1_set(cache_ref, key, value, ttl, conf)
  if not cache_ref then
    return
  end

  local now_ts = now_epoch(conf)
  if cache_ref.__fallback_store then
    fallback_set(cache_ref.__fallback_store, key, value, ttl, now_ts)
    return
  end

  cache_ref:set(key, value, ttl)
end

local function l1_delete(cache_ref, key)
  if not cache_ref then
    return
  end

  if cache_ref.__fallback_store then
    fallback_delete(cache_ref.__fallback_store, key)
    return
  end

  cache_ref:delete(key)
end

local function get_shared_dict(conf)
  local shm_name = type(conf) == "table" and conf.policy_cache_shm or nil
  if not is_non_empty_string(shm_name) then
    shm_name = "kong_cost_quota_cache"
  end

  if not (ngx and type(ngx.shared) == "table") then
    return nil
  end

  return ngx.shared[shm_name]
end

local function l2_data_key(key)
  return L2_DATA_PREFIX .. key
end

local function l2_version_key(key)
  return L2_VERSION_PREFIX .. key
end

local function l2_probe_key(key)
  return L2_PROBE_PREFIX .. key
end

function M.cache_enabled(conf)
  if type(conf) ~= "table" then
    return true
  end
  return conf.policy_cache_enabled ~= false
end

function M.resolve_policy_ttl(conf)
  local emergency_mode = type(conf) == "table" and conf.emergency_mode == true
  if emergency_mode then
    local ttl = to_integer(conf.policy_cache_ttl_emergency_sec, 5)
    if ttl < 5 then
      ttl = 5
    end
    if ttl > 10 then
      ttl = 10
    end
    return ttl
  end

  local ttl = to_integer(type(conf) == "table" and conf.policy_cache_ttl_sec or nil, 60)
  if ttl < 30 then
    ttl = 30
  end
  if ttl > 120 then
    ttl = 120
  end
  return ttl
end

function M.get_policy(conf, key)
  if not M.cache_enabled(conf) then
    return nil, nil
  end

  ensure_l1(conf)

  local l1_entry = l1_get(l1_cache, key, conf)
  if type(l1_entry) == "table" and is_non_empty_string(l1_entry.raw_policy) then
    return l1_entry, "cache_l1"
  end

  local dict = get_shared_dict(conf)
  if not dict then
    return nil, nil
  end

  local raw_policy = dict:get(l2_data_key(key))
  if not is_non_empty_string(raw_policy) then
    return nil, nil
  end

  local version = dict:get(l2_version_key(key))
  if not is_non_empty_string(version) then
    version = nil
  end

  local entry = {
    raw_policy = raw_policy,
    policy_version = version,
  }

  l1_set(l1_cache, key, entry, M.resolve_policy_ttl(conf), conf)
  return entry, "cache_l2"
end

function M.set_policy(conf, key, entry)
  if not M.cache_enabled(conf) then
    return false, nil
  end

  if type(entry) ~= "table" or not is_non_empty_string(entry.raw_policy) then
    return false, "cache entry must include raw_policy"
  end

  ensure_l1(conf)
  local ttl = M.resolve_policy_ttl(conf)
  l1_set(l1_cache, key, {
    raw_policy = entry.raw_policy,
    policy_version = entry.policy_version,
  }, ttl, conf)

  local dict = get_shared_dict(conf)
  if not dict then
    return true, nil
  end

  local ok, err = dict:set(l2_data_key(key), entry.raw_policy, ttl)
  if not ok then
    return false, "failed to set l2 cache data: " .. tostring(err)
  end

  if is_non_empty_string(entry.policy_version) then
    local version_ok, version_err = dict:set(l2_version_key(key), entry.policy_version, ttl)
    if not version_ok then
      return false, "failed to set l2 cache version: " .. tostring(version_err)
    end
  else
    dict:delete(l2_version_key(key))
  end

  return true, nil
end

function M.invalidate_policy(conf, key)
  ensure_l1(conf)
  l1_delete(l1_cache, key)
  l1_delete(l1_probe_cache, key)

  local dict = get_shared_dict(conf)
  if not dict then
    return
  end

  dict:delete(l2_data_key(key))
  dict:delete(l2_version_key(key))
  dict:delete(l2_probe_key(key))
end

-- version 검증용 probe는 짧은 TTL로 관리한다.
function M.should_probe_version(conf, key)
  if not M.cache_enabled(conf) then
    return false
  end

  ensure_l1(conf)
  local marker = l1_get(l1_probe_cache, key, conf)
  if marker then
    return false
  end

  local dict = get_shared_dict(conf)
  if dict then
    local l2_marker = dict:get(l2_probe_key(key))
    if l2_marker then
      local probe_ttl = resolve_probe_ttl(conf)
      l1_set(l1_probe_cache, key, 1, probe_ttl, conf)
      return false
    end
  end

  return true
end

function M.mark_probed(conf, key)
  if not M.cache_enabled(conf) then
    return
  end

  ensure_l1(conf)
  local probe_ttl = resolve_probe_ttl(conf)
  l1_set(l1_probe_cache, key, 1, probe_ttl, conf)

  local dict = get_shared_dict(conf)
  if not dict then
    return
  end

  dict:set(l2_probe_key(key), 1, probe_ttl)
end

-- 테스트에서 모듈 상태를 초기화하기 위한 헬퍼다.
function M._reset_for_test()
  l1_cache = nil
  l1_probe_cache = nil
  l1_cache_size = nil
end

return M
