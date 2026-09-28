-- Source policy for the MTA-STS integration tests.
local kumo = require 'kumo'

local TEST_DIR = os.getenv 'KUMOD_TEST_DIR'
local SINK_PORT = tonumber(os.getenv 'KUMOD_SMTP_SINK_PORT')
local CONTROL = os.getenv 'KUMOD_MTA_STS_CONTROL'
local sts_policies = {
  ['broken.example.com'] = [[version: STSv1
mode: enforce
mx: allowed.example.net
max_age: 86400]],
  ['good.example.com'] = [[version: STSv1
mode: enforce
mx: mail.good.example.com
max_age: 86400]],
  ['none.example.com'] = [[version: STSv1
mode: none
max_age: 86400]],
  ['enforce.example.com'] = [[version: STSv1
mode: enforce
mx: mail.shared.example.com
max_age: 86400]],
  ['testing.example.com'] = [[version: STSv1
mode: testing
mx: mail.shared.example.com
max_age: 86400]],
  ['secure.example.com'] = [[version: STSv1
mode: enforce
mx: mail.shared.example.com
max_age: 86400]],
  ['pkix.example.com'] = [[version: STSv1
mode: enforce
mx: mail.shared.example.com
max_age: 86400]],
  ['transition.example.com'] = [[version: STSv1
mode: none
max_age: 1]],
}

if CONTROL then
  sts_policies['none.example.com'] = 'version: STSv1\nmode: none\nmax_age: 1'
end
if os.getenv 'KUMOD_MTA_STS_EVICT_MX' then
  for _, domain in ipairs { 'none.example.com', 'transition.example.com' } do
    sts_policies[domain] = 'version: STSv1\nmode: none\nmax_age: 86400'
  end
end
if os.getenv 'KUMOD_MTA_STS_SHORT_DANE_MX' then
  for _, domain in ipairs { 'enforce.example.com', 'secure.example.com' } do
    sts_policies[domain] =
      sts_policies[domain]:gsub('max_age: 86400', 'max_age: 1')
  end
end

local function configure_dane(mode)
  local cert = assert(os.getenv 'KUMOD_SINK_TLS_CERT')
  local der = kumo.encode.base64_decode(
    cert
      :gsub('%-%-%-%-%-BEGIN CERTIFICATE%-%-%-%-%-', '')
      :gsub('%-%-%-%-%-END CERTIFICATE%-%-%-%-%-', '')
      :gsub('%s', '')
  )
  local tlsa = '3 0 0 ' .. kumo.encode.hex_encode(der)
  if mode == 'mismatch' then
    tlsa = '3 0 1 ' .. string.rep('00', 32)
  elseif mode == 'unusable' then
    tlsa = '1 0 0 ' .. kumo.encode.hex_encode(der)
  elseif mode == 'absent' then
    tlsa = nil
  end
  kumo.dns.configure_test_resolver {
    servfail = mode == 'servfail' and {
      '_' .. SINK_PORT .. '._tcp.mail.shared.example.com',
    } or nil,
    zones = {
      {
        zone = '$ORIGIN enforce.example.com.\n@ 600 MX 10 mail.shared.example.com.\n',
        secure = true,
      },
      {
        zone = '$ORIGIN secure.example.com.\n@ 600 MX 10 mail.shared.example.com.\n',
        secure = true,
      },
      {
        zone = '$ORIGIN pkix.example.com.\n@ 600 MX 10 mail.shared.example.com.\n',
        secure = false,
      },
      {
        zone = '$ORIGIN shared.example.com.\nmail 600 A 127.0.0.1\n'
          .. (
            tlsa
              and ('_' .. SINK_PORT .. '._tcp.mail 600 TLSA ' .. tlsa .. '\n')
            or ''
          ),
        secure = true,
      },
    },
  }
end

-- Test-only control channel: change policies after messages are in the ready
-- queue, acknowledge the update, and let the test expire the old snapshot.
kumo.on('test.update_sts', function()
  while true do
    local stop = io.open(CONTROL .. '/stop')
    if stop then
      stop:close()
      return
    end
    local input = io.open(CONTROL .. '/policies.json')
    if input then
      local changes = kumo.json_parse(input:read '*a')
      input:close()
      for domain, policy in pairs(changes) do
        sts_policies[domain] = policy
      end
      kumo.dns.configure_test_mta_sts(sts_policies)
      if os.getenv 'KUMOD_MTA_STS_EVICT_MX' then
        -- Evict MX_CACHE without expiring the source selector's cached route.
        -- LRU eviction retains the newest entry even at capacity zero. Insert
        -- a newer, unrelated entry so the affected domain is evictable.
        kumo.set_lruttl_cache_capacity('dns_resolver_mx', 1)
        kumo.dns.lookup_mx 'evict.example.com'
        kumo.set_lruttl_cache_capacity('dns_resolver_mx', 1)
        kumo.set_lruttl_cache_capacity('dns_resolver_mx', 65536)
      end
      os.remove(CONTROL .. '/policies.json')
      local ack = assert(io.open(CONTROL .. '/applied', 'w'))
      ack:close()
    end
    local dane = io.open(CONTROL .. '/dane-mode')
    if dane then
      local mode = dane:read '*a'
      dane:close()
      configure_dane(mode)
      os.remove(CONTROL .. '/dane-mode')
      local ack = assert(io.open(CONTROL .. '/dane-applied', 'w'))
      ack:close()
    end
    kumo.time.sleep(0.05)
  end
end)

kumo.on('init', function()
  kumo.configure_accounting_db_path(TEST_DIR .. '/accounting.db')

  kumo.start_esmtp_listener {
    listen = '127.0.0.1:0',
    relay_hosts = { '0.0.0.0/0' },
  }

  kumo.start_http_listener {
    listen = '127.0.0.1:0',
  }

  kumo.configure_local_logs {
    log_dir = TEST_DIR .. '/logs',
    max_segment_duration = '1s',
    meta = { 'promotions' },
  }

  kumo.define_spool {
    name = 'data',
    path = TEST_DIR .. '/data-spool',
  }

  kumo.define_spool {
    name = 'meta',
    path = TEST_DIR .. '/meta-spool',
  }

  -- broken.example.com publishes MX records, but its (mocked) MTA-STS policy
  -- is in enforce mode and permits none of those MX hosts, making it
  -- undeliverable until the policy is corrected. good.example.com publishes a
  -- policy that covers its MX host, so delivery proceeds normally.
  kumo.dns.configure_test_resolver {
    [[
$ORIGIN broken.example.com.
@    600 MX 10 mail.broken.example.com.
mail 600 A  127.0.0.1
]],
    [[
$ORIGIN good.example.com.
@    600 MX 10 mail.good.example.com.
mail 600 A  127.0.0.1
]],
    -- Same MX site, different receiver TLS policies.
    [[
$ORIGIN none.example.com.
@    600 MX 10 mail.shared.example.com.
]],
    [[
$ORIGIN testing.example.com.
@ 600 MX 10 mail.shared.example.com.
]],
    [[
$ORIGIN evict.example.com.
@ 600 MX 10 mail.shared.example.com.
]],
    [[
$ORIGIN sibling.example.com.
@ 600 MX 10 mail.shared.example.com.
]],
    [[
$ORIGIN unchanged.example.com.
@ 600 MX 10 mail.shared.example.com.
@ 600 MX 20 mail.other.example.com.
]],
    [[
$ORIGIN enforce.example.com.
@    600 MX 10 mail.shared.example.com.
]],
    [[
$ORIGIN shared.example.com.
mail 600 A 127.0.0.1
]],
    -- The transition test changes this policy after MX resolution, while
    -- the message remains associated with the original ready queue.
    [[
$ORIGIN transition.example.com.
@ 600 MX 10 mail.shared.example.com.
@ 600 MX 20 mail.other.example.com.
]],
    [[
$ORIGIN other.example.com.
mail 600 A 127.0.0.1
]],
  }

  if os.getenv 'KUMOD_MTA_STS_BACKUP' then
    kumo.dns.configure_test_resolver {
      '$ORIGIN none.example.com.\n@ 600 MX 10 mail.shared.example.com.\n@ 600 MX 20 mail.backup.example.com.\n',
      '$ORIGIN enforce.example.com.\n@ 600 MX 10 mail.shared.example.com.\n@ 600 MX 20 mail.backup.example.com.\n',
      '$ORIGIN shared.example.com.\nmail 600 A 127.0.0.1\n',
      '$ORIGIN backup.example.com.\nmail 600 A 127.0.0.1\n',
    }
    sts_policies['enforce.example.com'] = [[version: STSv1
mode: enforce
mx: mail.shared.example.com
mx: mail.backup.example.com
max_age: 86400]]
  end
  if os.getenv 'KUMOD_MTA_STS_COLLISION' then
    kumo.dns.configure_test_resolver {
      '$ORIGIN collision-a.example.com.\n@ 600 MX 10 a.x.targets.test.\n@ 600 MX 10 b.x.targets.test.\n@ 600 MX 10 c.y.targets.test.\n',
      '$ORIGIN collision-b.example.com.\n@ 600 MX 10 a.x.targets.test.\n@ 600 MX 10 b.y.targets.test.\n@ 600 MX 10 c.x.targets.test.\n',
      '$ORIGIN targets.test.\na.x 600 A 127.0.0.2\nb.x 600 A 127.0.0.1\nc.y 600 A 127.0.0.1\nb.y 600 A 127.0.0.1\nc.x 600 A 127.0.0.1\n',
    }
    sts_policies['collision-a.example.com'] =
      'version: STSv1\nmode: none\nmax_age: 86400'
    sts_policies['collision-b.example.com'] = [[version: STSv1
mode: enforce
mx: a.x.targets.test
mx: b.y.targets.test
mx: c.x.targets.test
max_age: 86400]]
  end
  if os.getenv 'KUMOD_MTA_STS_DANE' then
    configure_dane(os.getenv 'KUMOD_MTA_STS_DANE')
    if os.getenv 'KUMOD_MTA_STS_DANE' == 'unusable' then
      for _, domain in ipairs { 'enforce.example.com', 'secure.example.com' } do
        sts_policies[domain] = 'version: STSv1\nmode: none\nmax_age: 86400'
      end
    end
  end
  kumo.dns.configure_test_mta_sts(sts_policies)
  if CONTROL then
    kumo.dns.set_mx_negative_cache_ttl '1s'
    kumo.spawn_task { event_name = 'test.update_sts', args = {} }
  end
end)

kumo.on('get_queue_config', function(domain)
  -- Resolve MX records for each recipient domain instead of routing directly
  -- to the sink, so MTA-STS is evaluated before ready-queue rollup.
  return kumo.make_queue_config {
    protocol = nil,
    retry_interval = os.getenv 'KUMOD_MTA_STS_NO_RETRY' and '1h' or '2s',
  }
end)

kumo.on('get_egress_path_config', function(domain, _source_name, site_name)
  domain = domain:gsub(':%d+$', '')
  if
    domain == 'transition.example.com'
    and os.getenv 'KUMOD_TRANSITION_STS'
    and site_name ~= 'mail.other.example.com'
  then
    sts_policies['transition.example.com'] = [[version: STSv1
mode: enforce
mx: mail.other.example.com
max_age: 86400]]
    if os.getenv 'KUMOD_TRANSITION_STS' == 'impossible' then
      sts_policies['transition.example.com'] = [[version: STSv1
mode: enforce
mx: nowhere.example.net
max_age: 86400]]
    end
    kumo.dns.configure_test_mta_sts(sts_policies)
    -- Policy max_age expires the combined MX/policy result before the DNS TTL.
    kumo.time.sleep(2)
  end
  local shared = domain == 'none.example.com'
    or domain == 'enforce.example.com'
    or domain == 'pkix.example.com'
    or domain == 'secure.example.com'
    or domain == 'collision-a.example.com'
    or domain == 'collision-b.example.com'
    or domain == 'testing.example.com'
    or domain == 'transition.example.com'
    or domain == 'sibling.example.com'
    or domain == 'unchanged.example.com'
  local untrusted_tls = os.getenv 'KUMOD_UNTRUSTED_MTA_STS_TLS' == '1'
  return kumo.make_egress_path {
    enable_tls = os.getenv 'KUMOD_MTA_STS_TLS'
      or (
        shared and not untrusted_tls and 'Opportunistic'
        or 'OpportunisticInsecure'
      ),
    prohibited_hosts = {},
    -- Exclude the colliding sets' common host so the connected peer belongs
    -- only to the creator's set; do not rely on an OS-specific connect failure.
    skip_hosts = os.getenv 'KUMOD_MTA_STS_COLLISION' and { '127.0.0.2' }
      or nil,
    connection_limit = 1,
    reconnect_strategy = os.getenv 'KUMOD_MTA_STS_BACKUP'
        and 'ConnectNextHost'
      or nil,
    idle_timeout = os.getenv 'KUMOD_MTA_STS_BACKUP' and '10s' or nil,
    opportunistic_tls_reconnect_on_failed_handshake = os.getenv 'KUMOD_MTA_STS_FALLBACK'
      ~= nil,
    consecutive_connection_failures_before_delay = os.getenv 'KUMOD_MTA_STS_LIMIT'
          == 'backoff'
        and 0
      or nil,
    max_connection_rate = os.getenv 'KUMOD_MTA_STS_LIMIT' == 'rate' and '1/h'
      or nil,
    -- Direct the resolved 127.0.0.1 MX host at the sink.
    smtp_port = SINK_PORT,
    -- Keep the existing MX-filtering tests focused on resolution. The shared
    -- MX test applies each domain's resolved policy at connection setup.
    enable_mta_sts = shared and not os.getenv 'KUMOD_MTA_STS_NO_STS',
    enable_dane = os.getenv 'KUMOD_MTA_STS_DANE' ~= nil,
    tls_prefer_openssl = shared
      and os.getenv 'KUMOD_SINK_TLS_CERT' ~= nil
      and os.getenv 'KUMOD_MTA_STS_TLS_BACKEND' ~= 'rustls',
    aggressive_connection_opening = shared
      and os.getenv 'KUMOD_AGGRESSIVE_MTA_STS' == '1',
  }
end)

kumo.on('smtp_server_message_received', function(msg)
  if os.getenv 'KUMOD_MTA_STS_ROUTE_PORT' then
    msg:set_meta('routing_domain', msg:recipient().domain .. ':' .. SINK_PORT)
  end
end)

-- Count promotions so queue-continuity tests detect bulk re-insertion, not
-- merely eventual delivery of the unrelated messages.
kumo.on('throttle_insert_ready_queue', function(msg)
  local promotions = (msg:get_meta 'promotions' or 0) + 1
  msg:set_meta('promotions', promotions)
  if os.getenv 'KUMOD_MTA_STS_EVICT_MX' then
    assert(promotions <= 4, 'site-change reinsertion loop')
  end
end)
