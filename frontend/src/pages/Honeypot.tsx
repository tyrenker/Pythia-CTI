import { useState, useEffect, useRef, useMemo, Fragment } from 'react'
import { ComposableMap, Geographies, Geography } from 'react-simple-maps'
import { Radio, Activity, Users, AlertTriangle, WifiOff } from 'lucide-react'
import {
  useHoneypotCampaigns,
  useHoneypotDailyStats,
  useHoneypotRealtimeStats,
  type HoneypotEvent,
  type HoneypotCampaign,
} from '@/api/honeypot'
import { timeAgo } from '@/lib/utils'
import { cn } from '@/lib/utils'

const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: 'bg-blue-900/40 text-blue-300 border border-blue-700/40',
  dionaea: 'bg-purple-900/40 text-purple-300 border border-purple-700/40',
  honeytrap: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  mailoney: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
}

const STATUS_COLORS: Record<string, string> = {
  active: 'bg-green-900/40 text-green-300 border border-green-700/40',
  dormant: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
  archived: 'bg-[#2a2a3e] text-[#6b7280] border border-[#3a3a5e]',
}

const COUNTRY_FLAGS: Record<string, string> = {
  US: '🇺🇸', CN: '🇨🇳', RU: '🇷🇺', DE: '🇩🇪', GB: '🇬🇧', FR: '🇫🇷', JP: '🇯🇵',
  KR: '🇰🇷', BR: '🇧🇷', IN: '🇮🇳', NL: '🇳🇱', CA: '🇨🇦', AU: '🇦🇺', IT: '🇮🇹',
  ES: '🇪🇸', TR: '🇹🇷', PL: '🇵🇱', UA: '🇺🇦', SE: '🇸🇪', SG: '🇸🇬',
}

function HoneypotBadge({ type }: { type: string }) {
  return (
    <span className={cn('rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide', HONEYPOT_COLORS[type] ?? 'bg-[#2a2a3e] text-[#6b7280]')}>
      {type}
    </span>
  )
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={cn('rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide', STATUS_COLORS[status] ?? 'bg-[#2a2a3e] text-[#6b7280]')}>
      {status}
    </span>
  )
}

function AbuseScore({ score }: { score: number | null }) {
  if (score === null) return <span className="text-[#6b7280]">—</span>
  const color = score >= 71 ? 'text-red-400' : score >= 31 ? 'text-yellow-400' : 'text-green-400'
  return <span className={cn('font-mono font-semibold', color)}>{score}</span>
}

// ── Stats Strip ───────────────────────────────────────────────────────────────

function StatsStrip() {
  const { data: daily } = useHoneypotDailyStats()
  const { data: realtime } = useHoneypotRealtimeStats()
  const { data: campaigns = [] } = useHoneypotCampaigns({ status: 'active' })

  const uniqueIps = daily?.top_ips.length ?? 0
  const activeCampaigns = campaigns.length

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      {[
        { icon: Activity, label: 'Events (24h)', value: daily?.event_count ?? '—' },
        { icon: Radio, label: `Events (${realtime?.window_minutes ?? 5}min)`, value: realtime?.event_count ?? '—' },
        { icon: AlertTriangle, label: 'Active Campaigns', value: activeCampaigns },
        { icon: Users, label: 'Unique Attackers', value: uniqueIps },
      ].map(({ icon: Icon, label, value }) => (
        <div key={label} className="rounded-lg border border-[#2a2a3e] bg-bg-surface p-3">
          <div className="flex items-center gap-2 text-[#6b7280]">
            <Icon size={13} />
            <span className="text-[10px] uppercase tracking-wide">{label}</span>
          </div>
          <p className="mt-1 text-sm font-semibold text-text-primary">{String(value)}</p>
        </div>
      ))}
    </div>
  )
}

// ── Live Feed Tab ─────────────────────────────────────────────────────────────

function LiveFeedTab() {
  const [events, setEvents] = useState<HoneypotEvent[]>([])
  const [paused, setPaused] = useState(false)
  const [wsError, setWsError] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const pausedRef = useRef(false)

  useEffect(() => {
    pausedRef.current = paused
  }, [paused])

  useEffect(() => {
    const url = `ws://${window.location.host}/v1/honeypot/stream`
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onmessage = (e) => {
      if (pausedRef.current) return
      try {
        const ev = JSON.parse(e.data) as HoneypotEvent
        setEvents(prev => [ev, ...prev].slice(0, 100))
      } catch { /* skip malformed */ }
    }

    ws.onerror = () => setWsError('WebSocket error — connection may be down')
    ws.onclose = () => setWsError('WebSocket disconnected')

    return () => {
      ws.close()
    }
  }, [])

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        {wsError && (
          <div className="flex items-center gap-2 rounded-md border border-yellow-700/40 bg-yellow-900/20 px-3 py-2 text-xs text-yellow-300">
            <WifiOff size={12} />
            {wsError}
          </div>
        )}
        <button
          onClick={() => setPaused(p => !p)}
          className={cn(
            'ml-auto rounded-md border px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider transition-colors',
            paused
              ? 'border-[#00ff88]/40 bg-[#00ff88]/10 text-[#00ff88]'
              : 'border-[#2a2a3e] bg-bg-surface text-[#6b7280] hover:text-text-primary',
          )}
        >
          {paused ? 'Resume' : 'Pause'}
        </button>
      </div>

      {events.length === 0 && (
        <p className="text-sm text-[#6b7280]">Waiting for honeypot events via WebSocket...</p>
      )}

      <div className="space-y-1">
        {events.map((ev) => (
          <div
            key={ev.id}
            className="flex flex-wrap items-center gap-3 rounded border border-[#2a2a3e] bg-bg-surface px-3 py-2 font-mono text-xs"
          >
            <span className="shrink-0 text-[#6b7280]">
              {new Date(ev.event_timestamp).toLocaleTimeString()}
            </span>
            <HoneypotBadge type={ev.honeypot_type} />
            <span className={cn('font-semibold', ev.abuseipdb_score !== null && ev.abuseipdb_score >= 80 ? 'text-red-400' : 'text-[#e0e0e0]')}>
              {ev.attacker_ip}
            </span>
            {ev.attacker_country_code && (
              <span className="text-[#6b7280]">
                {COUNTRY_FLAGS[ev.attacker_country_code] ?? ''} {ev.attacker_country_code}
              </span>
            )}
            <span className="text-[#6b7280]">
              {ev.target_port ? `→ :${ev.target_port}` : ''}
              {ev.protocol ? ` (${ev.protocol})` : ''}
            </span>
            {ev.username_attempted && (
              <span className="flex items-center gap-1 text-[#6b7280]">
                creds: <span className="text-yellow-400">{ev.username_attempted}</span>
                {ev.password_attempted && (
                  <><span>:</span><span className="text-orange-400">{ev.password_attempted}</span></>
                )}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Campaigns Tab ─────────────────────────────────────────────────────────────

function CampaignsTab() {
  const { data: campaigns = [], isLoading } = useHoneypotCampaigns()
  const [expanded, setExpanded] = useState<string | null>(null)

  return (
    <div className="space-y-3">
      {isLoading && <p className="text-sm text-[#6b7280]">Loading campaigns...</p>}
      {!isLoading && campaigns.length === 0 && (
        <p className="text-sm text-[#6b7280]">No campaigns found.</p>
      )}

      <div className="overflow-x-auto rounded-lg border border-[#2a2a3e]">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#2a2a3e] bg-bg-surface text-left text-[11px] uppercase tracking-wide text-[#6b7280]">
              <th className="px-4 py-2">Name</th>
              <th className="px-4 py-2">Status</th>
              <th className="px-4 py-2">First Seen</th>
              <th className="px-4 py-2">Last Seen</th>
              <th className="px-4 py-2">Events</th>
              <th className="px-4 py-2">TTPs</th>
              <th className="px-4 py-2">Sigma</th>
            </tr>
          </thead>
          <tbody>
            {campaigns.map((c: HoneypotCampaign) => (
              <Fragment key={c.id}>
                <tr
                  onClick={() => setExpanded(expanded === c.id ? null : c.id)}
                  className="cursor-pointer border-b border-[#2a2a3e] hover:bg-bg-elevated"
                >
                  <td className="px-4 py-2 font-medium text-text-primary">{c.name}</td>
                  <td className="px-4 py-2"><StatusBadge status={c.status} /></td>
                  <td className="px-4 py-2 text-[#6b7280]">{timeAgo(c.first_seen)}</td>
                  <td className="px-4 py-2 text-[#6b7280]">{timeAgo(c.last_seen)}</td>
                  <td className="px-4 py-2 text-text-primary">{c.event_count}</td>
                  <td className="px-4 py-2 text-text-primary">{c.ttp_ids.length}</td>
                  <td className="px-4 py-2">
                    {c.sigma_rule_id
                      ? <span className="text-[10px] text-[#00ff88]">✓ rule</span>
                      : <span className="text-[10px] text-[#6b7280]">—</span>
                    }
                  </td>
                </tr>
                {expanded === c.id && (
                  <tr className="border-b border-[#2a2a3e] bg-bg-elevated">
                    <td colSpan={7} className="px-4 py-3">
                      <div className="space-y-3 text-xs">
                        <div>
                          <span className="font-mono uppercase tracking-[0.15em] text-[#6b7280]">IPs ({c.attacker_ips.length})</span>
                          <div className="mt-1 flex flex-wrap gap-1">
                            {c.attacker_ips.slice(0, 20).map(ip => (
                              <span key={ip} className="rounded bg-[#2a2a3e] px-1.5 py-0.5 font-mono text-[#e0e0e0]">{ip}</span>
                            ))}
                            {c.attacker_ips.length > 20 && (
                              <span className="text-[#6b7280]">+{c.attacker_ips.length - 20} more</span>
                            )}
                          </div>
                        </div>
                        {c.ttp_ids.length > 0 && (
                          <div>
                            <span className="font-mono uppercase tracking-[0.15em] text-[#6b7280]">TTPs</span>
                            <div className="mt-1 flex flex-wrap gap-1">
                              {c.ttp_ids.map(id => (
                                <span key={id} className="rounded bg-purple-900/30 px-1.5 py-0.5 font-mono text-purple-300">{id}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        {(c.credential_patterns.usernames.length > 0 || c.credential_patterns.passwords.length > 0) && (
                          <div>
                            <span className="font-mono uppercase tracking-[0.15em] text-[#6b7280]">Credential Patterns</span>
                            <p className="mt-1 text-[#9ca3af]">
                              {c.credential_patterns.usernames.slice(0, 5).join(', ')}
                              {c.credential_patterns.usernames.length > 5 ? ` +${c.credential_patterns.usernames.length - 5} more usernames` : ''}
                            </p>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Top Attackers Tab ─────────────────────────────────────────────────────────

function TopAttackersTab() {
  const { data: daily, isLoading } = useHoneypotDailyStats()

  return (
    <div className="space-y-3">
      {isLoading && <p className="text-sm text-[#6b7280]">Loading stats...</p>}
      {!isLoading && (!daily || daily.top_ips.length === 0) && (
        <p className="text-sm text-[#6b7280]">No attacker data yet.</p>
      )}

      {daily && daily.top_ips.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-[#2a2a3e]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#2a2a3e] bg-bg-surface text-left text-[11px] uppercase tracking-wide text-[#6b7280]">
                <th className="px-4 py-2">#</th>
                <th className="px-4 py-2">IP</th>
                <th className="px-4 py-2">Country</th>
                <th className="px-4 py-2">AbuseIPDB</th>
                <th className="px-4 py-2">GreyNoise</th>
                <th className="px-4 py-2">Events</th>
              </tr>
            </thead>
            <tbody>
              {daily.top_ips.map(([ip, count], idx) => (
                <tr key={ip} className="border-b border-[#2a2a3e] hover:bg-bg-elevated">
                  <td className="px-4 py-2 text-[#6b7280]">{idx + 1}</td>
                  <td className="px-4 py-2 font-mono font-medium text-text-primary">{ip}</td>
                  <td className="px-4 py-2 text-[#6b7280]">—</td>
                  <td className="px-4 py-2"><AbuseScore score={null} /></td>
                  <td className="px-4 py-2 text-[#6b7280]">—</td>
                  <td className="px-4 py-2 text-text-primary">{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── Geography Tab ─────────────────────────────────────────────────────────────

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'

// ISO 3166-1 alpha-2 → numeric (used by world-atlas topojson feature IDs)
const A2_TO_NUM: Record<string, number> = {
  AF:4,AL:8,DZ:12,AD:20,AO:24,AR:32,AM:51,AU:36,AT:40,AZ:31,BH:48,BD:50,
  BY:112,BE:56,BZ:84,BJ:204,BT:64,BO:68,BA:70,BR:76,BN:96,BG:100,BF:854,
  BI:108,CV:132,KH:116,CM:120,CA:124,CF:140,TD:148,CL:152,CN:156,CO:170,
  CD:180,CR:188,HR:191,CU:192,CY:196,CZ:203,DK:208,DO:214,EC:218,EG:818,
  SV:222,GQ:226,ER:232,EE:233,ET:231,FI:246,FR:250,GA:266,GM:270,GE:268,
  DE:276,GH:288,GR:300,GT:320,GN:324,GW:624,GY:328,HT:332,HN:340,HK:344,
  HU:348,IS:352,IN:356,ID:360,IR:364,IQ:368,IE:372,IL:376,IT:380,CI:384,
  JM:388,JP:392,JO:400,KZ:398,KE:404,KP:408,KR:410,KW:414,KG:417,LA:418,
  LV:428,LB:422,LS:426,LR:430,LY:434,LT:440,LU:442,MO:446,MK:807,MG:450,
  MW:454,MY:458,MV:462,ML:466,MT:470,MR:478,MX:484,MD:498,MN:496,ME:499,
  MA:504,MZ:508,MM:104,NA:516,NP:524,NL:528,NZ:554,NI:558,NE:562,NG:566,
  NO:578,OM:512,PK:586,PA:591,PG:598,PY:600,PE:604,PH:608,PL:616,PT:620,
  QA:634,RO:642,RU:643,RW:646,SA:682,SN:686,RS:688,SL:694,SG:702,SK:703,
  SI:705,SO:706,ZA:710,SS:728,ES:724,LK:144,SD:729,SR:740,SZ:748,SE:752,
  CH:756,SY:760,TW:158,TJ:762,TZ:834,TH:764,TL:626,TG:768,TT:780,TN:788,
  TR:792,TM:795,UG:800,UA:804,AE:784,GB:826,US:840,UY:858,UZ:860,VE:862,
  VN:704,YE:887,ZM:894,ZW:716,
}

const NUM_TO_A2 = Object.fromEntries(Object.entries(A2_TO_NUM).map(([a2, n]) => [n, a2]))

const COUNTRY_NAMES: Record<string, string> = {
  US:'United States',CN:'China',RU:'Russia',DE:'Germany',GB:'United Kingdom',
  FR:'France',JP:'Japan',KR:'South Korea',BR:'Brazil',IN:'India',NL:'Netherlands',
  CA:'Canada',AU:'Australia',IT:'Italy',ES:'Spain',TR:'Turkey',PL:'Poland',
  UA:'Ukraine',SE:'Sweden',SG:'Singapore',ID:'Indonesia',TH:'Thailand',VN:'Vietnam',
  IR:'Iran',SA:'Saudi Arabia',PK:'Pakistan',BD:'Bangladesh',
}

function mapColor(count: number, max: number): string {
  if (!count) return '#131320'
  // log scale: low → #1a3a2e, high → #00ff88
  const t = Math.log(count + 1) / Math.log(max + 1)
  const r = Math.round(0x1a * (1 - t))
  const g = Math.round(0x3a + (0xff - 0x3a) * t)
  const b = Math.round(0x2e + (0x88 - 0x2e) * t)
  return `rgb(${r},${g},${b})`
}

function GeographyTab() {
  const { data: daily, isLoading } = useHoneypotDailyStats()
  const [tooltip, setTooltip] = useState<{ x: number; y: number; label: string } | null>(null)

  const countByNumeric = useMemo(() => {
    const m: Record<number, number> = {}
    for (const [code, count] of daily?.top_countries ?? []) {
      const num = A2_TO_NUM[code]
      if (num) m[num] = count
    }
    return m
  }, [daily?.top_countries])

  const maxCount = useMemo(
    () => Math.max(1, ...Object.values(countByNumeric)),
    [countByNumeric],
  )

  const topCountries = daily?.top_countries.slice(0, 15) ?? []

  return (
    <div className="space-y-4">
      {isLoading && <p className="text-sm text-[#6b7280]">Loading geography...</p>}

      {/* World map */}
      <div className="relative overflow-hidden rounded-lg border border-[#2a2a3e] bg-[#0d0d1a]">
        <ComposableMap
          projectionConfig={{ scale: 147, center: [10, 10] }}
          style={{ width: '100%', height: 'auto' }}
        >
          <Geographies geography={GEO_URL}>
            {({ geographies }) =>
              geographies.map(geo => {
                const numId = Number(geo.id)
                const count = countByNumeric[numId] ?? 0
                const a2 = NUM_TO_A2[numId] ?? ''
                const fill = mapColor(count, maxCount)
                return (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill={fill}
                    stroke="#1e1e35"
                    strokeWidth={0.4}
                    onMouseEnter={(e: React.MouseEvent) => {
                      if (!a2) return
                      const name = COUNTRY_NAMES[a2] ?? a2
                      const flag = COUNTRY_FLAGS[a2] ?? ''
                      setTooltip({
                        x: e.clientX,
                        y: e.clientY,
                        label: `${flag} ${name} — ${count.toLocaleString()} event${count !== 1 ? 's' : ''}`,
                      })
                    }}
                    onMouseMove={(e: React.MouseEvent) => {
                      setTooltip(prev => prev ? { ...prev, x: e.clientX, y: e.clientY } : null)
                    }}
                    onMouseLeave={() => setTooltip(null)}
                    style={{
                      default: { outline: 'none', cursor: count ? 'crosshair' : 'default' },
                      hover:   { fill: count ? '#00ff88' : '#1e1e35', outline: 'none' },
                      pressed: { outline: 'none' },
                    }}
                  />
                )
              })
            }
          </Geographies>
        </ComposableMap>

        {/* Legend */}
        <div className="absolute bottom-3 left-4 flex items-center gap-2">
          <span className="font-mono text-[10px] text-[#6b7280]">Low</span>
          <div className="h-2 w-24 rounded-sm" style={{
            background: 'linear-gradient(to right, #1a3a2e, #00ff88)',
          }} />
          <span className="font-mono text-[10px] text-[#6b7280]">High</span>
        </div>

        <div className="absolute right-3 top-3 font-mono text-[10px] text-[#6b7280]">
          ATTACK ORIGIN MAP
        </div>
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="pointer-events-none fixed z-50 rounded border border-[#2a2a3e] bg-[#0d0d1a]/95 px-2.5 py-1.5 font-mono text-xs text-[#e0e0e0] shadow-lg backdrop-blur-sm"
          style={{ left: tooltip.x + 14, top: tooltip.y - 36 }}
        >
          {tooltip.label}
        </div>
      )}

      {/* Country bar chart below map */}
      {topCountries.length > 0 && (
        <div className="space-y-2">
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#6b7280]">
            // Top Origins (last 24 h)
          </p>
          {topCountries.map(([code, count]) => (
            <div key={code} className="flex items-center gap-3">
              <span className="w-24 shrink-0 font-mono text-xs text-[#9ca3af]">
                {COUNTRY_FLAGS[code] ?? ''} {COUNTRY_NAMES[code] ?? code}
              </span>
              <div className="flex-1 overflow-hidden rounded-sm bg-[#1e1e35]">
                <div
                  className="h-4 rounded-sm transition-all duration-500"
                  style={{
                    width: `${(count / (topCountries[0]?.[1] ?? 1)) * 100}%`,
                    background: mapColor(count, topCountries[0]?.[1] ?? 1),
                  }}
                />
              </div>
              <span className="w-14 shrink-0 text-right font-mono text-xs text-text-primary">
                {count.toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      )}

      {!isLoading && topCountries.length === 0 && (
        <p className="text-sm text-[#6b7280]">
          No geography data yet — events need GeoIP enrichment (MAXMIND_DB_PATH required).
        </p>
      )}
    </div>
  )
}

// ── Credentials Tab ───────────────────────────────────────────────────────────

function CredentialsTab() {
  const { data: daily, isLoading } = useHoneypotDailyStats()

  const usernames: [string, number][] = []
  const passwords: [string, number][] = []

  if (daily) {
    for (const [cred, count] of daily.top_credentials) {
      const parts = cred.split(':')
      if (parts.length >= 2) {
        const user = parts[0]
        const pass = parts.slice(1).join(':')
        if (user) usernames.push([user, count])
        if (pass) passwords.push([pass, count])
      }
    }
    usernames.sort((a, b) => b[1] - a[1])
    passwords.sort((a, b) => b[1] - a[1])
  }

  const maxUser = usernames[0]?.[1] ?? 1
  const maxPass = passwords[0]?.[1] ?? 1

  return (
    <div className="space-y-4">
      {isLoading && <p className="text-sm text-[#6b7280]">Loading credential data...</p>}

      <div className="grid gap-6 md:grid-cols-2">
        <div className="space-y-2">
          <p className="font-mono text-xs uppercase tracking-[0.2em] text-[#6b7280]/90">// Top Usernames</p>
          {usernames.slice(0, 15).map(([user, count]) => (
            <div key={user} className="flex items-center gap-3">
              <span className="w-28 shrink-0 truncate font-mono text-xs text-[#e0e0e0]">{user}</span>
              <div className="flex-1 overflow-hidden rounded-sm bg-[#2a2a3e]">
                <div
                  className="h-4 rounded-sm bg-blue-500/40 transition-all duration-300"
                  style={{ width: `${(count / maxUser) * 100}%` }}
                />
              </div>
              <span className="w-8 shrink-0 text-right font-mono text-xs text-[#6b7280]">{count}</span>
            </div>
          ))}
          {usernames.length === 0 && !isLoading && (
            <p className="text-xs text-[#6b7280]">No data yet.</p>
          )}
        </div>

        <div className="space-y-2">
          <p className="font-mono text-xs uppercase tracking-[0.2em] text-[#6b7280]/90">// Top Passwords</p>
          {passwords.slice(0, 15).map(([pass, count]) => (
            <div key={pass} className="flex items-center gap-3">
              <span className="w-28 shrink-0 truncate font-mono text-xs text-orange-300">{pass}</span>
              <div className="flex-1 overflow-hidden rounded-sm bg-[#2a2a3e]">
                <div
                  className="h-4 rounded-sm bg-orange-500/40 transition-all duration-300"
                  style={{ width: `${(count / maxPass) * 100}%` }}
                />
              </div>
              <span className="w-8 shrink-0 text-right font-mono text-xs text-[#6b7280]">{count}</span>
            </div>
          ))}
          {passwords.length === 0 && !isLoading && (
            <p className="text-xs text-[#6b7280]">No data yet.</p>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'live', label: 'Live Feed' },
  { id: 'campaigns', label: 'Campaigns' },
  { id: 'attackers', label: 'Top Attackers' },
  { id: 'geography', label: 'Geography' },
  { id: 'credentials', label: 'Credentials' },
] as const

type TabId = (typeof TABS)[number]['id']

export function Honeypot() {
  const [activeTab, setActiveTab] = useState<TabId>('live')

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Radio size={18} className="text-[#00ff88]" />
            <h1 className="text-lg font-semibold text-text-primary">Honeypot Monitor</h1>
          </div>
          <p className="mt-0.5 text-sm text-[#6b7280]">
            Live attacker telemetry from T-Pot and honeypot sensors
          </p>
        </div>
      </div>

      <StatsStrip />

      <div className="border-b border-[#2a2a3e]">
        <div className="flex gap-1">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                'px-4 py-2 text-sm font-medium transition-colors',
                activeTab === tab.id
                  ? 'border-b-2 border-[#00ff88] text-text-primary'
                  : 'text-[#6b7280] hover:text-text-primary',
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {activeTab === 'live' && <LiveFeedTab />}
      {activeTab === 'campaigns' && <CampaignsTab />}
      {activeTab === 'attackers' && <TopAttackersTab />}
      {activeTab === 'geography' && <GeographyTab />}
      {activeTab === 'credentials' && <CredentialsTab />}
    </div>
  )
}
