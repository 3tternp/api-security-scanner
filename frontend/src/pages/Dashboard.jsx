import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  BarChart2,
  TrendingUp,
  Eye,
  Plus,
  RefreshCw,
} from 'lucide-react'
import { getDashboardStats, getScans } from '../api.js'

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', color: 'bg-red-600', text: 'text-red-700' },
  high: { label: 'High', color: 'bg-orange-500', text: 'text-orange-600' },
  medium: { label: 'Medium', color: 'bg-yellow-400', text: 'text-yellow-600' },
  low: { label: 'Low', color: 'bg-blue-400', text: 'text-blue-600' },
  info: { label: 'Info', color: 'bg-gray-400', text: 'text-gray-500' },
}

const OWASP_ITEMS = [
  { id: 'API1', name: 'Broken Object Level Authorization', severity: 'Critical', key: 'api1' },
  { id: 'API2', name: 'Broken Authentication', severity: 'Critical', key: 'api2' },
  { id: 'API3', name: 'Broken Object Property Level Authorization', severity: 'Critical', key: 'api3' },
  { id: 'API4', name: 'Unrestricted Resource Consumption', severity: 'High', key: 'api4' },
  { id: 'API5', name: 'Broken Function Level Authorization', severity: 'Critical', key: 'api5' },
  { id: 'API6', name: 'Unrestricted Access to Sensitive Business Flows', severity: 'Critical', key: 'api6' },
  { id: 'API7', name: 'Server Side Request Forgery', severity: 'High', key: 'api7' },
  { id: 'API8', name: 'Security Misconfiguration', severity: 'Critical', key: 'api8' },
  { id: 'API9', name: 'Improper Inventory Management', severity: 'High', key: 'api9' },
  { id: 'API10', name: 'Unsafe Consumption of APIs', severity: 'High', key: 'api10' },
]

const StatCard = ({ title, value, icon: Icon, iconColor, borderColor, loading }) => (
  <div className={`bg-white rounded-xl shadow-sm border-l-4 ${borderColor} p-5 flex items-center gap-4`}>
    <div className={`p-3 rounded-full bg-opacity-10 ${iconColor.replace('text-', 'bg-').replace('-600', '-100').replace('-500', '-100')}`}>
      <Icon className={`w-6 h-6 ${iconColor}`} />
    </div>
    <div>
      <p className="text-sm text-gray-500 font-medium">{title}</p>
      {loading ? (
        <div className="h-7 w-16 bg-gray-200 animate-pulse rounded mt-1" />
      ) : (
        <p className="text-2xl font-bold text-gray-800">{value ?? '—'}</p>
      )}
    </div>
  </div>
)

const SeverityBar = ({ severityCounts, loading }) => {
  const keys = ['critical', 'high', 'medium', 'low', 'info']
  const total = keys.reduce((sum, k) => sum + (severityCounts?.[k] || 0), 0)

  if (loading) {
    return <div className="h-5 w-full bg-gray-200 animate-pulse rounded-full" />
  }

  if (!total) {
    return (
      <div className="h-5 w-full bg-gray-100 rounded-full flex items-center justify-center">
        <span className="text-xs text-gray-400">No findings yet</span>
      </div>
    )
  }

  return (
    <div>
      <div className="flex h-5 rounded-full overflow-hidden w-full">
        {keys.map((k) => {
          const count = severityCounts?.[k] || 0
          if (!count) return null
          const pct = (count / total) * 100
          return (
            <div
              key={k}
              className={`${SEVERITY_CONFIG[k].color} transition-all`}
              style={{ width: `${pct}%` }}
              title={`${SEVERITY_CONFIG[k].label}: ${count}`}
            />
          )
        })}
      </div>
      <div className="flex flex-wrap gap-3 mt-2">
        {keys.map((k) => {
          const count = severityCounts?.[k] || 0
          return (
            <div key={k} className="flex items-center gap-1.5 text-xs text-gray-600">
              <span className={`w-2.5 h-2.5 rounded-sm ${SEVERITY_CONFIG[k].color}`} />
              {SEVERITY_CONFIG[k].label}: <span className="font-semibold">{count}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

const StatusDot = ({ status }) => {
  const colors = {
    completed: 'bg-green-500',
    running: 'bg-blue-500 animate-pulse',
    failed: 'bg-red-500',
    pending: 'bg-gray-400',
  }
  return <span className={`inline-block w-2 h-2 rounded-full ${colors[status] || 'bg-gray-400'}`} />
}

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
  })

  const {
    data: scans,
    isLoading: scansLoading,
  } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => (await getScans()).data,
  })

  const recentScans = scans ? [...scans].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 5) : []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-sm text-gray-500 mt-0.5">API Security Scanner — Overview</p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => refetchStats()}
            className="flex items-center gap-2 px-3 py-2 text-sm text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50 transition"
          >
            <RefreshCw size={14} /> Refresh
          </button>
          <Link
            to="/scans"
            className="flex items-center gap-2 px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition"
          >
            <Plus size={14} /> New Scan
          </Link>
        </div>
      </div>

      {/* Error banner for stats */}
      {statsError && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 text-sm text-yellow-800">
          Could not load dashboard stats. Stats endpoint may not be available yet.
        </div>
      )}

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Scans"
          value={stats?.total_scans ?? scans?.length}
          icon={Shield}
          iconColor="text-blue-600"
          borderColor="border-blue-500"
          loading={statsLoading && scansLoading}
        />
        <StatCard
          title="Total Findings"
          value={stats?.total_findings}
          icon={AlertTriangle}
          iconColor="text-red-600"
          borderColor="border-red-500"
          loading={statsLoading}
        />
        <StatCard
          title="Open Issues"
          value={stats?.open_findings}
          icon={Clock}
          iconColor="text-orange-500"
          borderColor="border-orange-400"
          loading={statsLoading}
        />
        <StatCard
          title="Scans Running"
          value={stats?.running_scans ?? scans?.filter((s) => s.status === 'running').length}
          icon={TrendingUp}
          iconColor="text-green-600"
          borderColor="border-green-500"
          loading={statsLoading && scansLoading}
        />
      </div>

      {/* Severity Breakdown */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
        <div className="flex items-center gap-2 mb-3">
          <BarChart2 className="w-4 h-4 text-gray-500" />
          <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide">Severity Breakdown</h2>
        </div>
        <SeverityBar
          severityCounts={stats ? {
            critical: stats.critical_findings,
            high: stats.high_findings,
            medium: stats.medium_findings,
            low: stats.low_findings,
            info: stats.info_findings,
          } : undefined}
          loading={statsLoading}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* OWASP API Top 10 */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-gray-500" />
            <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide">OWASP API Top 10</h2>
          </div>
          <div className="space-y-2">
            {OWASP_ITEMS.map((item) => {
              const count = stats ? (stats.findings_by_rule?.[item.id] ?? 0) : null
              const severityBadge =
                item.severity === 'Critical'
                  ? 'bg-red-100 text-red-700'
                  : 'bg-orange-100 text-orange-700'
              return (
                <div
                  key={item.id}
                  className="flex items-center justify-between py-1.5 border-b border-gray-50 last:border-0"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-xs font-bold text-gray-500 w-10 shrink-0">{item.id}</span>
                    <span className="text-xs text-gray-700 truncate">{item.name}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0 ml-2">
                    {statsLoading ? (
                      <div className="h-4 w-6 bg-gray-200 animate-pulse rounded" />
                    ) : count !== null ? (
                      <span className={`text-xs font-bold ${count > 0 ? 'text-red-600' : 'text-green-600'}`}>
                        {count > 0 ? count : '✓'}
                      </span>
                    ) : null}
                    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full ${severityBadge}`}>
                      {item.severity}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Recent Scans */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Eye className="w-4 h-4 text-gray-500" />
              <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide">Recent Scans</h2>
            </div>
            <Link to="/scans" className="text-xs text-blue-600 hover:underline">View all</Link>
          </div>

          {scansLoading ? (
            <div className="space-y-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-14 bg-gray-100 animate-pulse rounded-lg" />
              ))}
            </div>
          ) : recentScans.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 text-center">
              <Shield className="w-10 h-10 text-gray-300 mb-2" />
              <p className="text-sm text-gray-400">No scans yet</p>
              <Link
                to="/scans"
                className="mt-3 text-sm text-blue-600 hover:underline flex items-center gap-1"
              >
                <Plus size={12} /> Start your first scan
              </Link>
            </div>
          ) : (
            <div className="space-y-2">
              {recentScans.map((scan) => (
                <Link
                  key={scan.id}
                  to={`/scans/${scan.id}`}
                  className="flex items-center justify-between p-3 rounded-lg hover:bg-gray-50 border border-gray-100 transition group"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <StatusDot status={scan.status} />
                      <span className="text-sm font-medium text-gray-800 truncate max-w-[200px]">
                        {scan.target_url}
                      </span>
                    </div>
                    <p className="text-xs text-gray-400 mt-0.5 ml-4">
                      {new Date(scan.created_at).toLocaleString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0 ml-2">
                    <span
                      className={`text-[10px] font-semibold px-2 py-0.5 rounded-full capitalize ${
                        scan.status === 'completed'
                          ? 'bg-green-100 text-green-700'
                          : scan.status === 'running'
                          ? 'bg-blue-100 text-blue-700'
                          : scan.status === 'failed'
                          ? 'bg-red-100 text-red-700'
                          : 'bg-gray-100 text-gray-600'
                      }`}
                    >
                      {scan.status}
                    </span>
                    <CheckCircle className="w-3.5 h-3.5 text-gray-300 group-hover:text-blue-400 transition" />
                  </div>
                </Link>
              ))}
            </div>
          )}

          {!scansLoading && recentScans.length > 0 && (
            <div className="mt-4 pt-3 border-t border-gray-100 flex gap-3">
              <Link
                to="/scans"
                className="flex-1 text-center text-sm text-white bg-blue-600 hover:bg-blue-700 py-2 rounded-lg transition"
              >
                <span className="flex items-center justify-center gap-1.5">
                  <Plus size={13} /> New Scan
                </span>
              </Link>
              <Link
                to="/scans"
                className="flex-1 text-center text-sm text-gray-700 border border-gray-200 hover:bg-gray-50 py-2 rounded-lg transition"
              >
                <span className="flex items-center justify-center gap-1.5">
                  <Eye size={13} /> View All Scans
                </span>
              </Link>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default Dashboard
