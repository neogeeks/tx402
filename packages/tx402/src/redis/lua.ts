/**
 * The server-side atoms for {@link RedisSpendStore} (SPEC §3.4, §3.4a, §12.2).
 *
 * Each spend transition is ONE `EVAL` (Lua) script — not a client read-decide-write, which a
 * concurrent caller could interleave, and not `FUNCTION LOAD`, whose support on managed Redis
 * (Upstash) is spotty (O14). The scripts are content-addressed by `EVALSHA` with an `EVAL`
 * fallback, so they load lazily and survive a `SCRIPT FLUSH`.
 *
 * Three invariants the Lua enforces that a naive adapter would get wrong:
 *
 *  - **Backend-authoritative time (§3.4a).** Windowing reads `redis.call('TIME')` INSIDE the
 *    atom, never the caller's clock, so fleet clock skew cannot double-spend the shared cap. A
 *    test-only clock override is passed as `now` (ARGV) — the harness pins it; production always
 *    passes `""`, which selects `TIME`. The caller's `nowEpochMs` never windows anything.
 *  - **Unbounded-width arithmetic (§12.2, P1-7b).** A single money input is up to 78 atomic
 *    digits and the lifetime accumulators grow past that, while Lua numbers are IEEE doubles
 *    (exact only to 2^53). Every AMOUNT is therefore a decimal STRING and every sum/compare
 *    goes through the string big-integer helpers below — no `INCRBY`, no truncation. Only
 *    TIMESTAMPS (epoch-ms, 13 digits, < 2^53) stay Lua numbers.
 *  - **`{ns:scope}` single-slot (§12.2).** Every key an atom touches for a scope — the reservation
 *    hashes across all assets, the indices, the counters, the freeze/pin/limit keys — shares the
 *    `{ns:scope}` hash tag, so the whole atom is one Cluster slot. The global `{ns}:global-frozen`
 *    key is a DIFFERENT slot, which is exactly why atomic global freeze is single-instance only
 *    (declared via `capabilities.atomicGlobalFreeze`). The `reserve`/`snapshot` atoms read it ONLY
 *    when the caller passes the `checkGlobalFrozen` flag (`"1"`), which the adapter sets from
 *    `atomicGlobalFreeze`: `true` on single-instance (read it), `false` on Cluster (skip it, so the
 *    atom stays single-slot and never touches the foreign-slot key — SPEC §5.2/§12.2).
 *
 * Results are `cjson`-encoded on the way out and parsed by the adapter, so a refusal is
 * structured data the client turns into the exact typed error (`BudgetExceededError`,
 * `SpendScopeFrozenError`, `RecipientUnpinnedError`, `ConfigurationError`) — never a Redis error
 * reply, which would lose the taxonomy details. The Lua is byte-identical to the copy embedded in
 * the Python adapter (`tx402/stores/redis.py`); it is the one source of truth for Redis
 * behaviour, so the two SDKs share a backend semantics, not just an interface.
 */

/**
 * Shared prelude: big-integer decimal helpers, the backend-clock resolver, the `{ns:scope}` key
 * builders, recipient canonicalization, and small reply constructors. Prepended to every script.
 */
const PRELUDE = String.raw`
-- ── non-negative decimal big-integer helpers (amounts exceed 2^53) ──────────────────────────
local function strip(s)
  local t = string.gsub(s, '^0+', '')
  if t == '' then return '0' end
  return t
end
local function bigCmp(a, b)
  a = strip(a); b = strip(b)
  if #a ~= #b then if #a < #b then return -1 else return 1 end end
  if a < b then return -1 elseif a > b then return 1 else return 0 end
end
local function bigAdd(a, b)
  local i, j, carry = #a, #b, 0
  local out = {}
  while i > 0 or j > 0 or carry > 0 do
    local da = (i > 0) and (string.byte(a, i) - 48) or 0
    local db = (j > 0) and (string.byte(b, j) - 48) or 0
    local s = da + db + carry
    if s >= 10 then s = s - 10; carry = 1 else carry = 0 end
    out[#out + 1] = string.char(s + 48)
    i = i - 1; j = j - 1
  end
  local r = {}
  for k = #out, 1, -1 do r[#r + 1] = out[k] end
  return strip(table.concat(r))
end
-- a - b, assuming a >= b >= 0 (true for every counter decrement here)
local function bigSub(a, b)
  a = strip(a); b = strip(b)
  local i, j, borrow = #a, #b, 0
  local out = {}
  while i > 0 do
    local da = string.byte(a, i) - 48
    local db = (j > 0) and (string.byte(b, j) - 48) or 0
    local s = da - db - borrow
    if s < 0 then s = s + 10; borrow = 1 else borrow = 0 end
    out[#out + 1] = string.char(s + 48)
    i = i - 1; j = j - 1
  end
  local r = {}
  for k = #out, 1, -1 do r[#r + 1] = out[k] end
  return strip(table.concat(r))
end

-- ── backend-authoritative time (§3.4a): override when non-empty, else redis TIME ─────────────
local function resolveNow(override)
  if override ~= nil and override ~= '' then return tonumber(override) end
  local t = redis.call('TIME')
  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
end

-- ── {ns:scope} single-slot key builders ──────────────────────────────────────────────────────
local NS, SCOPE = ARGV[1], ARGV[2]
local BASE = '{' .. NS .. ':' .. SCOPE .. '}'
local function resKey(asset, id) return BASE .. ':res:' .. asset .. ':' .. id end
local function resIdx(asset) return BASE .. ':res:' .. asset .. ':idx' end
local function cmtKey(asset, id) return BASE .. ':cmt:' .. asset .. ':' .. id end
local function cmtIdx(asset) return BASE .. ':cmt:' .. asset .. ':idx' end
local function totalKey(asset) return BASE .. ':' .. asset .. ':total' end
local function exposedKey(asset) return BASE .. ':' .. asset .. ':exposed' end
local function limitsKey(asset) return BASE .. ':' .. asset .. ':limits' end
local FROZEN_KEY = BASE .. ':frozen'
local GLOBAL_FROZEN_KEY = '{' .. NS .. '}:global-frozen'
local function pinsKey(network) return BASE .. ':pins:' .. network end
local RECIPIENT_REQUIRED_KEY = BASE .. ':recipient-required'
local TOFU_ENABLED_KEY = BASE .. ':tofu-enabled'

local function num(v, dflt)
  if v == false or v == nil then return dflt end
  return tonumber(v)
end
local function counter(key)
  local v = redis.call('GET', key)
  if v == false or v == nil then return '0' end
  return v
end
-- eip155 → lowercase hex (SPEC §6.4); every other family verbatim. Idempotent.
local function canon(network, value)
  if value == '' then return value end
  if string.sub(network, 1, 7) == 'eip155:' then return string.lower(value) end
  return value
end
local function split(s)
  local out = {}
  if s == nil or s == '' then return out end
  for piece in string.gmatch(s, '[^\n]+') do out[#out + 1] = piece end
  return out
end
local function reservationTable(asset, id)
  local h = redis.call('HGETALL', resKey(asset, id))
  local m = {}
  for k = 1, #h, 2 do m[h[k]] = h[k + 1] end
  return {
    reservationId = m.reservationId,
    policyScope = m.policyScope,
    requestFingerprint = m.requestFingerprint,
    assetId = m.assetId,
    amountAtomic = m.amountAtomic,
    createdAtEpochMs = tonumber(m.createdAtEpochMs),
    expiresAtEpochMs = tonumber(m.expiresAtEpochMs),
    state = m.state,
  }
end
`;

/**
 * `reserve` (SPEC §3.4 steps 1–7). ARGV: 1 ns, 2 scope, 3 asset, 4 id, 5 requestFingerprint,
 * 6 amountAtomic, 7 maxPerHourAtomic, 8 maxTotalAtomic|"", 9 recipientNetwork|"",
 * 10 recipientCanonical|"", 11 recipientEnforcement|"", 12 nowOverride|"", 13 ttlMs, 14 windowMs,
 * 15 checkGlobalFrozen ("1" reads the foreign-slot global-freeze key; "" skips it on Cluster).
 */
export const RESERVE = String.raw`${PRELUDE}
local asset = ARGV[3]
local id = ARGV[4]
local fp = ARGV[5]
local amount = ARGV[6]
local callerPerHour = ARGV[7]
local callerTotal = ARGV[8]
local recipientNetwork = ARGV[9]
local recipientCanonical = ARGV[10]
local enforcement = ARGV[11]
local now = resolveNow(ARGV[12])
local ttlMs = tonumber(ARGV[13])
local windowMs = tonumber(ARGV[14])
local checkGlobalFrozen = ARGV[15]

-- step 1 — reservation-id reuse (first): identical replay returns the existing record.
if redis.call('EXISTS', resKey(asset, id)) == 1 then
  local existing = reservationTable(asset, id)
  if existing.requestFingerprint ~= fp or existing.amountAtomic ~= amount then
    return cjson.encode({ ok = false, kind = 'idreuse' })
  end
  return cjson.encode({ ok = true, reservation = existing, recipientPinEstablished = false })
end

-- step 2 — freeze (D-B1): this scope OR the global "*" scope. The global key is a foreign slot,
-- so it is consulted ONLY when the store declares atomicGlobalFreeze (checkGlobalFrozen == '1');
-- on Cluster the flag is '' and the atom never touches it, staying single-slot (§5.2/§12.2).
if redis.call('EXISTS', FROZEN_KEY) == 1 then
  return cjson.encode({ ok = false, kind = 'frozen', frozenScope = SCOPE })
end
if checkGlobalFrozen == '1' and redis.call('EXISTS', GLOBAL_FROZEN_KEY) == 1 then
  return cjson.encode({ ok = false, kind = 'frozen', frozenScope = '*' })
end

-- step 3 — recipient assertion, driven by the STORE's administered source (SPEC §3.4 step 3).
local presented = nil
if recipientCanonical ~= '' and recipientNetwork ~= '' then
  presented = canon(recipientNetwork, recipientCanonical)
end
local required = redis.call('EXISTS', RECIPIENT_REQUIRED_KEY) == 1
local pinEstablished = false
if required and presented == nil then
  return cjson.encode({ ok = false, kind = 'recipient', reason = 'assertion-required' })
end
if presented ~= nil then
  local pin = redis.call('HGETALL', pinsKey(recipientNetwork))
  if #pin > 0 then
    local pm = {}
    for k = 1, #pin, 2 do pm[pin[k]] = pin[k + 1] end
    local expected = split(pm.recipients)
    local matched = false
    for i = 1, #expected do
      expected[i] = canon(recipientNetwork, expected[i])
      if expected[i] == presented then matched = true end
    end
    if not matched then
      local reason = 'pin-mismatch'
      if pm.source == 'admin-allowlist' then reason = 'not-allowlisted' end
      return cjson.encode({
        ok = false, kind = 'recipient', reason = reason,
        network = recipientNetwork, presentedRecipient = presented, expectedRecipients = expected,
      })
    end
  elseif enforcement == 'tofu' then
    -- no record + TOFU: claim-if-absent IN THIS ATOM (reads tofuEnabled inside, closing the TOCTOU).
    if redis.call('EXISTS', TOFU_ENABLED_KEY) ~= 1 then
      return cjson.encode({
        ok = false, kind = 'config',
        configPath = 'recipientPolicy', reason = 'recipient-tofu-not-provisioned',
      })
    end
    redis.call('HSET', pinsKey(recipientNetwork), 'recipients', presented, 'source', 'tofu')
    pinEstablished = true
  end
  -- enforcement 'allowlist'/'off'/'' with no record → admit, no claim (allowlist is advisory here).
end

-- step 4 — resolve caps against any administered limit (min; a caller cap ABOVE it is rejected).
local lim = redis.call('HGETALL', limitsKey(asset))
local lm = {}
for k = 1, #lim, 2 do lm[lim[k]] = lim[k + 1] end
local adminPerHour = lm.maxPerHourAtomic
local adminTotal = lm.maxTotalAtomic
if adminPerHour ~= nil and bigCmp(callerPerHour, adminPerHour) > 0 then
  return cjson.encode({ ok = false, kind = 'config', configPath = 'policy.maxPerHour', reason = 'cap-exceeds-administered' })
end
local effPerHour = callerPerHour
local effTotal = nil
if callerTotal ~= '' then
  if adminTotal ~= nil and bigCmp(callerTotal, adminTotal) > 0 then
    return cjson.encode({ ok = false, kind = 'config', configPath = 'policy.maxTotal', reason = 'cap-exceeds-administered' })
  end
  effTotal = callerTotal
elseif adminTotal ~= nil then
  effTotal = adminTotal
end

-- windowed sums (also lazily expires reserved records whose TTL passed).
local cutoff = now - windowMs
local committed = '0'
for _, cid in ipairs(redis.call('ZRANGEBYSCORE', cmtIdx(asset), cutoff, now)) do
  local a = redis.call('HGET', cmtKey(asset, cid), 'amountAtomic')
  if a then committed = bigAdd(committed, a) end
end
local reserved = '0'
local exposedRolling = '0'
for _, rid in ipairs(redis.call('ZRANGEBYSCORE', resIdx(asset), cutoff, now)) do
  local rk = resKey(asset, rid)
  local state = redis.call('HGET', rk, 'state')
  if state == 'reserved' then
    if num(redis.call('HGET', rk, 'expiresAtEpochMs'), 0) <= now then
      redis.call('HSET', rk, 'state', 'expired')
    else
      reserved = bigAdd(reserved, redis.call('HGET', rk, 'amountAtomic'))
    end
  elseif state == 'exposed' then
    exposedRolling = bigAdd(exposedRolling, redis.call('HGET', rk, 'amountAtomic'))
  end
end

-- step 5 — per-hour cap over the rolling window; the three terms are disjoint.
if bigCmp(bigAdd(bigAdd(bigAdd(committed, reserved), exposedRolling), amount), effPerHour) > 0 then
  return cjson.encode({
    ok = false, kind = 'budget', capKind = 'per-hour',
    requestedAtomic = amount, capAtomic = effPerHour,
    committedAtomic = committed, reservedAtomic = bigAdd(reserved, exposedRolling),
  })
end

-- step 6 — cumulative cap, only when one is in effect. exposed counted once (via the counter).
if effTotal ~= nil then
  local cumCommitted = counter(totalKey(asset))
  local exposedTotal = counter(exposedKey(asset))
  local sum = bigAdd(bigAdd(bigAdd(cumCommitted, exposedTotal), reserved), amount)
  if bigCmp(sum, effTotal) > 0 then
    return cjson.encode({
      ok = false, kind = 'budget', capKind = 'cumulative',
      requestedAtomic = amount, capAtomic = effTotal,
      committedAtomic = cumCommitted, reservedAtomic = bigAdd(exposedTotal, reserved),
    })
  end
end

-- step 7 — insert.
local createdAt = now
local expiresAt = now + ttlMs
redis.call('HSET', resKey(asset, id),
  'reservationId', id, 'policyScope', SCOPE, 'requestFingerprint', fp, 'assetId', asset,
  'amountAtomic', amount, 'createdAtEpochMs', tostring(createdAt),
  'expiresAtEpochMs', tostring(expiresAt), 'state', 'reserved')
redis.call('ZADD', resIdx(asset), createdAt, id)
return cjson.encode({
  ok = true,
  reservation = {
    reservationId = id, policyScope = SCOPE, requestFingerprint = fp, assetId = asset,
    amountAtomic = amount, createdAtEpochMs = createdAt, expiresAtEpochMs = expiresAt,
    state = 'reserved',
  },
  recipientPinEstablished = pinEstablished,
})
`;

/**
 * `commit` (SPEC §3.4 matrix). ARGV: 1 ns, 2 scope, 3 asset, 4 id, 5 committedAtOverride|"",
 * 6 settlementId|"". Works late: an `exposed` record whose window passed still commits and counts.
 */
export const COMMIT = String.raw`${PRELUDE}
local asset = ARGV[3]
local id = ARGV[4]
local now = resolveNow(ARGV[5])
local settlementId = ARGV[6]
local ck = cmtKey(asset, id)
local rk = resKey(asset, id)

if redis.call('EXISTS', ck) == 1 then
  local h = redis.call('HGETALL', ck)
  local m = {}
  for k = 1, #h, 2 do m[h[k]] = h[k + 1] end
  return cjson.encode({ ok = true, entry = {
    reservationId = m.reservationId, requestFingerprint = m.requestFingerprint,
    assetId = m.assetId, amountAtomic = m.amountAtomic,
    committedAtEpochMs = tonumber(m.committedAtEpochMs), settlementId = m.settlementId,
  } })
end
if redis.call('EXISTS', rk) == 0 then
  return cjson.encode({ ok = false, kind = 'config', configPath = 'reservationRef', reason = 'reservation-not-found' })
end
local state = redis.call('HGET', rk, 'state')
if state == 'reserved' and num(redis.call('HGET', rk, 'expiresAtEpochMs'), 0) <= now then
  redis.call('HSET', rk, 'state', 'expired'); state = 'expired'
end
if state == 'released' then
  return cjson.encode({ ok = false, kind = 'config', configPath = 'reservation.lifecycle', reason = 'released-cannot-commit' })
end
if state == 'expired' then
  return cjson.encode({ ok = false, kind = 'config', configPath = 'reservation.lifecycle', reason = 'expired-cannot-commit' })
end
local amount = redis.call('HGET', rk, 'amountAtomic')
local fp = redis.call('HGET', rk, 'requestFingerprint')
redis.call('HSET', ck, 'reservationId', id, 'requestFingerprint', fp, 'assetId', asset,
  'amountAtomic', amount, 'committedAtEpochMs', tostring(now))
if settlementId ~= '' then redis.call('HSET', ck, 'settlementId', settlementId) end
redis.call('HSET', rk, 'state', 'committed')
redis.call('ZADD', cmtIdx(asset), now, id)
redis.call('SET', totalKey(asset), bigAdd(counter(totalKey(asset)), amount))
if state == 'exposed' then
  redis.call('SET', exposedKey(asset), bigSub(counter(exposedKey(asset)), amount))
end
local entry = { reservationId = id, requestFingerprint = fp, assetId = asset,
  amountAtomic = amount, committedAtEpochMs = now }
if settlementId ~= '' then entry.settlementId = settlementId end
return cjson.encode({ ok = true, entry = entry })
`;

/** `release` (SPEC §3.4 matrix). ARGV: 1 ns, 2 scope, 3 asset, 4 id, 5 nowOverride|"". */
export const RELEASE = String.raw`${PRELUDE}
local asset = ARGV[3]
local id = ARGV[4]
local now = resolveNow(ARGV[5])
local rk = resKey(asset, id)
if redis.call('EXISTS', rk) == 0 then
  return cjson.encode({ ok = false, kind = 'config', configPath = 'reservationRef', reason = 'reservation-not-found' })
end
local state = redis.call('HGET', rk, 'state')
if state == 'reserved' and num(redis.call('HGET', rk, 'expiresAtEpochMs'), 0) <= now then
  redis.call('HSET', rk, 'state', 'expired'); state = 'expired'
end
if state == 'reserved' then
  redis.call('HSET', rk, 'state', 'released')
elseif state == 'exposed' then
  redis.call('HSET', rk, 'state', 'released')
  redis.call('SET', exposedKey(asset), bigSub(counter(exposedKey(asset)), redis.call('HGET', rk, 'amountAtomic')))
end
return cjson.encode({ ok = true, reservation = reservationTable(asset, id) })
`;

/** `expose` — the durable pre-transmission fence (SPEC §7). ARGV: 1 ns, 2 scope, 3 asset, 4 id, 5 nowOverride|"". */
export const EXPOSE = String.raw`${PRELUDE}
local asset = ARGV[3]
local id = ARGV[4]
local now = resolveNow(ARGV[5])
local rk = resKey(asset, id)
if redis.call('EXISTS', rk) == 0 then
  return cjson.encode({ ok = false, kind = 'config', configPath = 'reservationRef', reason = 'reservation-not-found' })
end
local state = redis.call('HGET', rk, 'state')
if state == 'reserved' and num(redis.call('HGET', rk, 'expiresAtEpochMs'), 0) <= now then
  redis.call('HSET', rk, 'state', 'expired'); state = 'expired'
end
if state == 'exposed' then
  return cjson.encode({ ok = true, reservation = reservationTable(asset, id) })
end
if state ~= 'reserved' then
  return cjson.encode({ ok = false, kind = 'config', configPath = 'reservation.lifecycle', reason = 'reservation-already-terminal' })
end
redis.call('HSET', rk, 'state', 'exposed')
redis.call('SET', exposedKey(asset), bigAdd(counter(exposedKey(asset)), redis.call('HGET', rk, 'amountAtomic')))
return cjson.encode({ ok = true, reservation = reservationTable(asset, id) })
`;

/**
 * `resolveExposed` (admin). ARGV: 1 ns, 2 scope, 3 asset, 4 id, 5 outcome (committed|released),
 * 6 nowOverride|"". Exactly `commit(exposed)`/`release(exposed)`; refuses a non-exposed record.
 */
export const RESOLVE_EXPOSED = String.raw`${PRELUDE}
local asset = ARGV[3]
local id = ARGV[4]
local outcome = ARGV[5]
local now = resolveNow(ARGV[6])
local rk = resKey(asset, id)
if redis.call('EXISTS', rk) == 0 then
  return cjson.encode({ ok = false, kind = 'config', configPath = 'reservationRef', reason = 'reservation-not-found' })
end
local state = redis.call('HGET', rk, 'state')
if state == 'reserved' then
  return cjson.encode({ ok = false, kind = 'config', configPath = 'reservation.lifecycle', reason = 'reservation-not-exposed' })
end
if state ~= 'exposed' then
  return cjson.encode({ ok = false, kind = 'config', configPath = 'reservation.lifecycle', reason = 'reservation-already-terminal' })
end
local amount = redis.call('HGET', rk, 'amountAtomic')
if outcome == 'committed' then
  local fp = redis.call('HGET', rk, 'requestFingerprint')
  redis.call('HSET', cmtKey(asset, id), 'reservationId', id, 'requestFingerprint', fp, 'assetId', asset,
    'amountAtomic', amount, 'committedAtEpochMs', tostring(now))
  redis.call('HSET', rk, 'state', 'committed')
  redis.call('ZADD', cmtIdx(asset), now, id)
  redis.call('SET', totalKey(asset), bigAdd(counter(totalKey(asset)), amount))
  redis.call('SET', exposedKey(asset), bigSub(counter(exposedKey(asset)), amount))
else
  redis.call('HSET', rk, 'state', 'released')
  redis.call('SET', exposedKey(asset), bigSub(counter(exposedKey(asset)), amount))
end
return cjson.encode({ ok = true })
`;

/**
 * `getBudgetState` snapshot (SPEC §3.2). ARGV: 1 ns, 2 scope, 3 asset, 4 nowOverride|"", 5 windowMs,
 * 6 checkGlobalFrozen ("1" folds the foreign-slot global-freeze key into `frozen`; "" skips it on
 * Cluster). Lazily expires + GCs out-of-window terminal records (an `exposed` record is never
 * expired/GC'd).
 */
export const SNAPSHOT = String.raw`${PRELUDE}
local asset = ARGV[3]
local now = resolveNow(ARGV[4])
local windowMs = tonumber(ARGV[5])
local checkGlobalFrozen = ARGV[6]
local cutoff = now - windowMs

-- GC committed reservations+entries once their commit falls out of the window.
for _, cid in ipairs(redis.call('ZRANGEBYSCORE', cmtIdx(asset), '-inf', '(' .. cutoff)) do
  redis.call('DEL', cmtKey(asset, cid))
  redis.call('ZREM', cmtIdx(asset), cid)
  redis.call('DEL', resKey(asset, cid))
  redis.call('ZREM', resIdx(asset), cid)
end

local committed = '0'
local entries = {}
for _, cid in ipairs(redis.call('ZRANGEBYSCORE', cmtIdx(asset), cutoff, now)) do
  local h = redis.call('HGETALL', cmtKey(asset, cid))
  local m = {}
  for k = 1, #h, 2 do m[h[k]] = h[k + 1] end
  if m.amountAtomic then
    committed = bigAdd(committed, m.amountAtomic)
    entries[#entries + 1] = {
      reservationId = m.reservationId, requestFingerprint = m.requestFingerprint,
      assetId = m.assetId, amountAtomic = m.amountAtomic,
      committedAtEpochMs = tonumber(m.committedAtEpochMs), settlementId = m.settlementId,
    }
  end
end

local reserved = '0'
local exposedRolling = '0'
local reservations = {}
for _, rid in ipairs(redis.call('ZRANGE', resIdx(asset), 0, -1)) do
  local rk = resKey(asset, rid)
  local state = redis.call('HGET', rk, 'state')
  if state ~= false and state ~= nil then
    if state == 'reserved' and num(redis.call('HGET', rk, 'expiresAtEpochMs'), 0) <= now then
      redis.call('HSET', rk, 'state', 'expired'); state = 'expired'
    end
    -- GC an out-of-window terminal reservation (never an exposed one).
    local createdAt = num(redis.call('HGET', rk, 'createdAtEpochMs'), 0)
    if state ~= 'exposed' and state ~= 'committed' and state ~= 'reserved' and createdAt < cutoff then
      redis.call('DEL', rk); redis.call('ZREM', resIdx(asset), rid)
    else
      local r = reservationTable(asset, rid)
      reservations[#reservations + 1] = r
      if createdAt >= cutoff and createdAt <= now then
        if state == 'reserved' then
          reserved = bigAdd(reserved, r.amountAtomic)
        elseif state == 'exposed' then
          exposedRolling = bigAdd(exposedRolling, r.amountAtomic)
        end
      end
    end
  end
end

local cumCommitted = counter(totalKey(asset))
local exposedTotal = counter(exposedKey(asset))
local cumConsumed = bigAdd(bigAdd(cumCommitted, exposedTotal), reserved)
local rollingConsumed = bigAdd(bigAdd(committed, reserved), exposedRolling)
local frozen = redis.call('EXISTS', FROZEN_KEY) == 1
if not frozen and checkGlobalFrozen == '1' and redis.call('EXISTS', GLOBAL_FROZEN_KEY) == 1 then
  frozen = true
end

local lim = redis.call('HGETALL', limitsKey(asset))
local lm = {}
for k = 1, #lim, 2 do lm[lim[k]] = lim[k + 1] end

local function avail(cap, consumed)
  if bigCmp(cap, consumed) < 0 then return '0' end
  return bigSub(cap, consumed)
end

local out = {
  ok = true, storeKind = 'redis', policyScope = SCOPE, assetId = asset,
  committedAtomic = committed, reservedAtomic = reserved, exposedAtomic = exposedTotal,
  cumulativeCommittedAtomic = cumCommitted, cumulativeConsumedAtomic = cumConsumed,
  frozen = frozen, entries = entries, reservations = reservations,
}
if lm.maxPerHourAtomic ~= nil then
  out.perHourLimitAtomic = lm.maxPerHourAtomic
  out.availablePerHourAtomic = avail(lm.maxPerHourAtomic, rollingConsumed)
end
if lm.maxTotalAtomic ~= nil then
  out.cumulativeLimitAtomic = lm.maxTotalAtomic
  out.availableCumulativeAtomic = avail(lm.maxTotalAtomic, cumConsumed)
end
return cjson.encode(out)
`;

/** `listExposed` (SPEC §7). ARGV: 1 ns, 2 scope, 3 asset. Enumerates unresolved exposed records. */
export const LIST_EXPOSED = String.raw`${PRELUDE}
local asset = ARGV[3]
local out = {}
for _, rid in ipairs(redis.call('ZRANGE', resIdx(asset), 0, -1)) do
  if redis.call('HGET', resKey(asset, rid), 'state') == 'exposed' then
    out[#out + 1] = reservationTable(asset, rid)
  end
end
return cjson.encode(out)
`;

/**
 * `setBudgetLimits` (SPEC §4.3). ARGV: 1 ns, 2 scope, 3 asset, 4 maxPerHourAtomic|"",
 * 5 maxTotalAtomic|"". ONE atom — DEL then a conditional HSET — so a concurrent reserve reading the
 * limits key observes the whole OLD cap or the whole NEW cap, never a torn value, and a failure
 * cannot leave the cap deleted (the old client-side DEL-then-HSET could, O26). Replace semantics: an
 * absent field is removed, matching MemorySpendStore/DO. `{ns:scope}` single-slot, Cluster-safe.
 */
export const SET_LIMITS = String.raw`${PRELUDE}
local asset = ARGV[3]
local key = limitsKey(asset)
redis.call('DEL', key)
local fields = {}
if ARGV[4] ~= '' then fields[#fields + 1] = 'maxPerHourAtomic'; fields[#fields + 1] = ARGV[4] end
if ARGV[5] ~= '' then fields[#fields + 1] = 'maxTotalAtomic'; fields[#fields + 1] = ARGV[5] end
if #fields > 0 then redis.call('HSET', key, unpack(fields)) end
return cjson.encode({ ok = true })
`;
