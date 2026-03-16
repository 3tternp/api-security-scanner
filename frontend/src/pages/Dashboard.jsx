import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Shield,
  AlertTriangle,
  Clock,
  TrendingUp,
  Plus,
  RefreshCw,
  Activity,
  CheckCircle2,
  XCircle,
  Zap,
  Target,
  Eye,
  ArrowUpRight,
  BarChart3,
  Bug,
} from 'lucide-react'
import { getDashboardStats, getScans } from '../api.js'

// ─── Constants ────────────────────────────────────────────────────────────────

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', bar: 'bg-red-500',    text: 'text-red-500',    badge: 'bg-red-500/10 text-red-400 border-red-500/20' },
  high:     { label: 'High',     bar: 'bg-orange-500', text: 'text-orange-500', badge: 'bg-orange-500/10 text-orange-400 border-orange-500/20' },
  medium:   { label: 'Medium',   bar: 'bg-amber-400',  text: 'text-amber-500',  badge: 'bg-amber-400/10 text-amber-400 border-amber-400/20' },
  low:      { label: 'Low',      bar: 'bg-blue-500',   text: 'text-blue-500',   badge: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
  info:     { label: 'Info',     bar: 'bg-slate-400',  text: 'text-slate-400',  badge: 'bg-slate-400/10 text-slate-400 border-slate-400/20' },
}

const OWASP_ITEMS = [
  { id: 'API1',  name: 'Broken Object Level Authorization',             key: 'API1',  severity: 'critical' },
  { id: 'API2',  name: 'Broken Authentication',                        key: 'API2',  severity: 'critical' },
  { id: 'API3',  name: 'Broken Object Property Level Authorization',   key: 'API3',  severity: 'critical' },
  { id: 'API4',  name: 'Unrestricted Resource Consumption',            key: 'API4',  severity: 'high' },
  { id: 'API5',  name: 'Broken Function Level Authorization',          key: 'API5',  severity: 'critical' },
  { id: 'API6',  name: 'Unrestricted Access to Sensitive Business Flows', key: 'API6', severity: 'critical' },
  { id: 'API7',  name: 'Server Side Request Forgery',                  key: 'API7',  severity: 'high' },
  { id: 'API8',  name: 'Security Misconfiguration',                    key: 'API8',  severity: 'critical' },
  { id: 'API9',  name: 'Improper Inventory Management',                key: 'API9',  severity: 'high' },
  { id: 'API10', name: 'Unsafe Consumption of APIs',                   key: 'API10', severity: 'high' },
]

// ─── Sub-components ───────────────────────────────────────────────────────────

const Skeleton = ({ className }) => (
  <div className={`animate-pulse bg-slate-200 rounded-lg ${className}`} />
)

const MetricCard = ({ title, value, sub, icon: Icon, accent, loading }) => {
  const accents = {
    blue:   { bg: 'from-blue-500 to-blue-600',   ring: 'ring-blue-100' },
    red:    { bg: 'from-red-500 to-rose-600',     ring: 'ring-red-100' },
    orange: { bg: 'from-orange-500 to-amber-500', ring: 'ring-orange-100' },
    green:  { bg: 'from-emerald-500 to-teal-500', ring: 'ring-emerald-100' },
  }
  const a = accents[accent] || accents.blue

  return (
    <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-5 flex items-center gap-4 hover:shadow-md transition-shadow">
      <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${a.bg} flex items-center justify-center shadow-lg ring-4 ${a.ring} shrink-0`}>
        <Icon size={22} className="text-white" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide">{title}</p>
        {loading ? (
          <Skeleton className="h-8 w-16 mt-1" />
        ) : (
          <p className="text-3xl font-black text-slate-800 leading-tight">{value ?? '—'}</p>
        )}
        {sub && !loading && (
          <p className="text-xs text-slate-400 mt-0.5">{sub}</p>
        )}
      </div>
    </div>
  )
}

const SeverityRow = ({ label, count, total, colorClass, loading }) => {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs font-semibold text-slate-500 w-14 shrink-0">{label}</span>
      <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
        {loading ? (
          <div className="h-full w-1/3 bg-slate-200 animate-pulse rounded-full" />
        ) : (
          <div
            className={`h-full ${colorClass} rounded-full transition-all duration-500`}
            style={{ width: `${pct}%` }}
          />
        )}
      </div>
      <span className="text-xs font-bold text-slate-700 w-8 text-right shrink-0">
        {loading ? '--' : count}
      </span>
      <span className="text-xs text-slate-400 w-8 shrink-0">
        {loading ? '' : `${pct}%`}
      </span>
    </div>
  )
}

const RiskScore = ({ stats, loading }) => {
  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 py-4">
        <Skeleton className="w-24 h-24 rounded-full" />
        <Skeleton className="w-20 h-4" />
      </div>
    )
  }

  const total = stats?.total_findings ?? 0
  const critical = stats?.critical_findings ?? 0
  const high = stats?.high_findings ?? 0

  const score = total === 0
    ? 0
    : Math.min(100, Math.round((critical * 10 + high * 5) / Math.max(total, 1) * 10))

  const config =
    score === 0  ? { label: 'Clean',    ring: 'ring-emerald-400', text: 'text-emerald-500', shadow: 'shadow-emerald-100' } :
    score < 30   ? { label: 'Low',      ring: 'ring-blue-400',    text: 'text-blue-500',    shadow: 'shadow-blue-100' }    :
    score < 60   ? { label: 'Medium',   ring: 'ring-amber-400',   text: 'text-amber-500',   shadow: 'shadow-amber-100' }   :
    score < 80   ? { label: 'High',     ring: 'ring-orange-400',  text: 'text-orange-500',  shadow: 'shadow-orange-100' }  :
                   { label: 'Critical', ring: 'ring-red-500',      text: 'text-red-600',     shadow: 'shadow-red-100' }

  return (
    <div className="flex flex-col items-center justify-center py-2 gap-3">
      <div className={`w-28 h-28 rounded-full ring-8 ${config.ring} flex flex-col items-center justify-center shadow-xl ${config.shadow}`}>
        <span className={`text-4xl font-black ${config.text}`}>{score}</span>
        <span className="text-[10px] text-slate-400 uppercase tracking-widest">/ 100</span>
      </div>
      <div className="text-center">
        <p className={`text-sm font-bold ${config.text}`}>{config.label} Risk</p>
        {total > 0 ? (
          <p className="text-xs text-slate-400 mt-0.5">{critical} critical · {high} high</p>
        ) : (
          <p className="text-xs text-slate-400 mt-0.5">No findings yet</p>
        )}
      </div>
    </div>
  )
}

const OWASPRow = ({ item, count, loading }) => {
  const sev = SEVERITY_CONFIG[item.severity] || SEVERITY_CONFIG.info
  return (
    <div className="flex items-center gap-2 py-2 border-b border-slate-50 last:border-0 group">
      <span className="text-[10px] font-black text-slate-400 w-10 shrink-0">{item.id}</span>
      <span className="text-xs text-slate-600 flex-1 truncate group-hover:text-slate-800 transition-colors" title={item.name}>
        {item.name}
      </span>
      {loading ? (
        <Skeleton className="w-8 h-4" />
      ) : count > 0 ? (
        <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${sev.badge}`}>{count}</span>
      ) : (
        <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
      )}
      <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full border shrink-0 ${sev.badge}`}>
        {item.severity.charAt(0).toUpperCase() + item.severity.slice(1)}
      </span>
    </div>
  )
}

const StatusBadge = ({ status }) => {
  const cfg = {
    completed: 'bg-emerald-100 text-emerald-700',
    running:   'bg-blue-100 text-blue-700',
    failed:    'bg-red-100 text-red-700',
    pending:   'bg-slate-100 text-slate-600',
  }
  return (
    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full capitalize shrink-0 ${cfg[status] || cfg.pending}`}>
      {status}
    </span>
  )
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────

const Dashboard = () => {
  const {
    data: stats,
    isLoading: statsLoading,
    error: statsError,
    refetch: refetchStats,
  } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: async () => (await getDashboardStats()).data,
    retry: 1,
    refetchInterval: 15_000,
  })

  const { data: scans, isLoading: scansLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => (await getScans()).data,
    refetchInterval: 15_000,
  })

  const recentScans = scans
    ? [...scans].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 6)
    : []

  const totalFindings = stats?.total_findings ?? 0
  const sevKeys = ['critical', 'high', 'medium', 'low', 'info']
  const severityCounts = {
    critical: stats?.critical_findings ?? 0,
    high:     stats?.high_findings ?? 0,
    medium:   stats?.medium_findings ?? 0,
    low:      stats?.low_findings ?? 0,
    info:     stats?.info_findings ?? 0,
  }

  const completionRate = stats && stats.total_scans > 0
    ? Math.round((stats.completed_scans / stats.total_scans) * 100)
    : null

  const now = new Date()
  const greeting =
    now.getHours() < 12 ? 'Good morning' :
    now.getHours() < 17 ? 'Good afternoon' : 'Good evening'

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-xs font-medium text-slate-400">{greeting}</span>
            <span className="w-1 h-1 rounded-full bg-slate-300" />
            <span className="text-xs text-slate-400">
              {now.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' })}
            </span>
          </div>
          <h1 className="text-2xl font-black text-slate-900 flex items-center gap-2">
            <Target size={22} className="text-cyan-500" />
            Security Dashboard
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">Real-time API vulnerability monitoring</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetchStats()}
            className="flex items-center gap-1.5 px-3 py-2 text-sm text-slate-600 border border-slate-200 rounded-xl hover:bg-slate-50 transition bg-white shadow-sm"
          >
            <RefreshCw size={13} /> Refresh
          </button>
          <Link
            to="/scans"
            className="flex items-center gap-1.5 px-4 py-2 text-sm bg-gradient-to-r from-cyan-500 to-blue-600 text-white rounded-xl hover:opacity-90 transition shadow-md shadow-cyan-500/20 font-semibold"
          >
            <Plus size={14} /> New Scan
          </Link>
        </div>
      </div>

      {statsError && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-3 text-sm text-amber-800 flex items-center gap-2">
          <AlertTriangle size={14} className="shrink-0" />
          Dashboard stats unavailable — backend may be starting up.
        </div>
      )}

      {/* Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Scans"
          value={stats?.total_scans ?? scans?.length}
          sub={completionRate != null ? `${completionRate}% completed` : undefined}
          icon={Shield}
          accent="blue"
          loading={statsLoading && scansLoading}
        />
        <MetricCard
          title="Total Findings"
          value={stats?.total_findings}
          sub={stats?.critical_findings > 0 ? `${stats.critical_findings} critical` : 'No critical issues'}
          icon={Bug}
          accent="red"
          loading={statsLoading}
        />
        <MetricCard
          title="Open Issues"
          value={stats?.open_findings}
          sub="Require attention"
          icon={AlertTriangle}
          accent="orange"
          loading={statsLoading}
        />
        <MetricCard
          title="Scans Running"
          value={stats?.running_scans ?? scans?.filter((s) => s.status === 'running').length}
          sub="Active right now"
          icon={Activity}
          accent="green"
          loading={statsLoading && scansLoading}
        />
      </div>

      {/* Severity Breakdown + Risk Score */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-white rounded-2xl border border-slate-100 shadow-sm p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <BarChart3 size={16} className="text-slate-400" />
              <h2 className="text-sm font-bold text-slate-700 uppercase tracking-wide">Severity Breakdown</h2>
            </div>
            {!statsLoading && totalFindings > 0 && (
              <span className="text-xs text-slate-400">{totalFindings} total findings</span>
            )}
          </div>

          {!statsLoading && totalFindings === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <CheckCircle2 size={32} className="text-emerald-300 mb-2" />
              <p className="text-sm font-semibold text-slate-500">No findings yet</p>
              <p className="text-xs text-slate-400">Run a scan to see results here</p>
            </div>
          ) : (
            <div className="space-y-3">
              {sevKeys.map((k) => (
                <SeverityRow
                  key={k}
                  label={SEVERITY_CONFIG[k].label}
                  count={severityCounts[k]}
                  total={totalFindings}
                  colorClass={SEVERITY_CONFIG[k].bar}
                  loading={statsLoading}
                />
              ))}
              {!statsLoading && totalFindings > 0 && (
                <div className="pt-2 flex h-2 rounded-full overflow-hidden gap-px">
                  {sevKeys.map((k) => {
                    const c = severityCounts[k]
                    if (!c) return null
                    return (
                      <div
                        key={k}
                        title={`${SEVERITY_CONFIG[k].label}: ${c}`}
                        className={`${SEVERITY_CONFIG[k].bar}`}
                        style={{ width: `${(c / totalFindings) * 100}%` }}
                      />
                    )
                  })}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-5">
          <div className="flex items-center gap-2 mb-1">
            <Zap size={16} className="text-slate-400" />
            <h2 className="text-sm font-bold text-slate-700 uppercase tracking-wide">Risk Score</h2>
          </div>
          <RiskScore stats={stats} loading={statsLoading} />
        </div>
      </div>

      {/* OWASP Top 10 + Recent Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* OWASP */}
        <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Shield size={16} className="text-slate-400" />
              <h2 className="text-sm font-bold text-slate-700 uppercase tracking-wide">OWASP API Top 10</h2>
            </div>
            {!statsLoading && stats && (
              <span className="text-xs text-slate-400">
                {OWASP_ITEMS.filter((i) => !(stats.owasp_counts?.[i.key] > 0)).length}/10 clean
              </span>
            )}
          </div>
          <div>
            {OWASP_ITEMS.map((item) => (
              <OWASPRow
                key={item.id}
                item={item}
                count={stats?.owasp_counts?.[item.key] ?? 0}
                loading={statsLoading}
              />
            ))}
          </div>
        </div>

        {/* Recent Scans */}
        <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Eye size={16} className="text-slate-400" />
              <h2 className="text-sm font-bold text-slate-700 uppercase tracking-wide">Recent Scans</h2>
            </div>
            <Link to="/scans" className="text-xs text-cyan-600 hover:text-cyan-700 flex items-center gap-0.5 font-medium">
              View all <ArrowUpRight size={10} />
            </Link>
          </div>

          {scansLoading ? (
            <div className="space-y-3">
              {[1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-14" />)}
            </div>
          ) : recentScans.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 text-center">
              <Shield size={32} className="text-slate-200 mb-2" />
              <p className="text-sm font-semibold text-slate-400">No scans yet</p>
              <Link to="/scans" className="mt-3 flex items-center gap-1 text-sm text-cyan-600 hover:text-cyan-700 font-medium">
                <Plus size={12} /> Start your first scan
              </Link>
            </div>
          ) : (
            <div className="space-y-1.5">
              {recentScans.map((scan) => (
                <Link
                  key={scan.id}
                  to={`/scans/${scan.id}`}
                  className="flex items-center gap-3 p-3 rounded-xl border border-slate-100 hover:border-cyan-200 hover:bg-cyan-50/40 transition group"
                >
                  <span className={`w-2 h-2 rounded-full shrink-0 ${
                    scan.status === 'completed' ? 'bg-emerald-500' :
                    scan.status === 'running'   ? 'bg-blue-500 animate-pulse' :
                    scan.status === 'failed'    ? 'bg-red-500' : 'bg-slate-400'
                  }`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-slate-700 truncate group-hover:text-cyan-700 transition">
                      {scan.target_url}
                    </p>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <span className="text-xs text-slate-400">{new Date(scan.created_at).toLocaleDateString()}</span>
                      {scan.status === 'completed' && scan.finding_count != null && (
                        <>
                          <span className="text-slate-300">·</span>
                          <span className={`text-xs font-semibold ${scan.finding_count > 0 ? 'text-red-500' : 'text-emerald-500'}`}>
                            {scan.finding_count} finding{scan.finding_count !== 1 ? 's' : ''}
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                  <StatusBadge status={scan.status} />
                </Link>
              ))}
            </div>
          )}

          {!scansLoading && recentScans.length > 0 && (
            <div className="mt-3 pt-3 border-t border-slate-100">
              <Link
                to="/scans"
                className="flex items-center justify-center gap-2 w-full py-2 text-sm font-semibold text-white bg-gradient-to-r from-cyan-500 to-blue-600 rounded-xl hover:opacity-90 transition shadow shadow-cyan-500/20"
              >
                <Plus size={14} /> New Scan
              </Link>
            </div>
          )}
        </div>
      </div>

      {/* Dark stats footer bar */}
      {!statsLoading && stats && (
        <div className="bg-slate-900 rounded-2xl p-5 flex flex-wrap items-center justify-around gap-6">
          {[
            { label: 'Completed',       value: stats.completed_scans,   icon: CheckCircle2, color: 'text-emerald-400' },
            { label: 'Running',         value: stats.running_scans,     icon: Activity,     color: 'text-blue-400' },
            { label: 'Critical Issues', value: stats.critical_findings, icon: XCircle,      color: 'text-red-400' },
            { label: 'Open Findings',   value: stats.open_findings,     icon: Clock,        color: 'text-amber-400' },
            { label: 'Total Findings',  value: stats.total_findings,    icon: TrendingUp,   color: 'text-slate-300' },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="flex items-center gap-2.5">
              <Icon size={18} className={color} />
              <div>
                <p className="text-xl font-black text-white leading-tight">{value}</p>
                <p className="text-[10px] text-slate-500 uppercase tracking-wide">{label}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default Dashboard
