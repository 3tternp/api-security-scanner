import { useEffect, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  ScanSearch,
  Users as UsersIcon,
  LogOut,
  Shield,
  ChevronLeft,
  ChevronRight,
  Activity,
} from 'lucide-react'
import { getMe } from '../api.js'

const NAV_ITEMS = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scans', icon: ScanSearch, label: 'Scans' },
]

const NavItem = ({ to, icon: Icon, label, collapsed, active }) => (
  <Link
    to={to}
    title={collapsed ? label : undefined}
    className={`
      flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-150
      ${active
        ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
        : 'text-slate-400 hover:text-slate-100 hover:bg-slate-700/60'
      }
      ${collapsed ? 'justify-center' : ''}
    `}
  >
    <Icon
      size={18}
      className={`shrink-0 ${active ? 'text-cyan-400' : ''}`}
    />
    {!collapsed && <span className="truncate">{label}</span>}
    {active && !collapsed && (
      <span className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0" />
    )}
  </Link>
)

const Sidebar = ({ setIsAuthenticated }) => {
  const location = useLocation()
  const navigate = useNavigate()
  const [currentUser, setCurrentUser] = useState(null)
  const [collapsed, setCollapsed] = useState(false)

  useEffect(() => {
    getMe()
      .then((res) => setCurrentUser(res.data))
      .catch(() => {})
  }, [])

  const handleLogout = () => {
    localStorage.removeItem('token')
    setIsAuthenticated(false)
    navigate('/login')
  }

  const isAdmin = currentUser?.role === 'admin'

  return (
    <aside
      className={`
        flex flex-col bg-slate-900 border-r border-slate-700/50
        transition-all duration-200 ease-in-out shrink-0
        ${collapsed ? 'w-[64px]' : 'w-[220px]'}
      `}
      style={{ minHeight: '100vh' }}
    >
      {/* Logo */}
      <div className={`flex items-center gap-2.5 px-4 py-5 border-b border-slate-700/50 ${collapsed ? 'justify-center px-2' : ''}`}>
        <div className="w-8 h-8 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center shrink-0 shadow-lg shadow-cyan-500/20">
          <Shield size={16} className="text-white" />
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <p className="text-sm font-bold text-white leading-tight truncate">API Scanner</p>
            <p className="text-[10px] text-slate-500 leading-tight">Security Platform</p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
        {!collapsed && (
          <p className="text-[10px] font-semibold text-slate-600 uppercase tracking-widest px-3 mb-2">
            Navigation
          </p>
        )}
        {NAV_ITEMS.map(({ to, icon, label }) => (
          <NavItem
            key={to}
            to={to}
            icon={icon}
            label={label}
            collapsed={collapsed}
            active={to === '/' ? location.pathname === '/' : location.pathname.startsWith(to)}
          />
        ))}

        {isAdmin && (
          <NavItem
            to="/users"
            icon={UsersIcon}
            label="Users"
            collapsed={collapsed}
            active={location.pathname === '/users'}
          />
        )}

        {!collapsed && (
          <div className="pt-3 mt-3 border-t border-slate-700/50">
            <p className="text-[10px] font-semibold text-slate-600 uppercase tracking-widest px-3 mb-2">
              Status
            </p>
            <div className="flex items-center gap-2 px-3 py-2">
              <Activity size={14} className="text-emerald-400 shrink-0" />
              <span className="text-xs text-slate-400">Scanner Online</span>
              <span className="ml-auto w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse shrink-0" />
            </div>
          </div>
        )}
      </nav>

      {/* User + Logout */}
      <div className="border-t border-slate-700/50 px-2 py-3 space-y-1">
        {currentUser && !collapsed && (
          <div className="flex items-center gap-2.5 px-3 py-2 rounded-xl bg-slate-800/60 mb-2">
            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white text-xs font-bold shrink-0">
              {(currentUser.email?.[0] || 'U').toUpperCase()}
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-slate-200 truncate">{currentUser.email}</p>
              <p className="text-[10px] text-slate-500 capitalize">{currentUser.role}</p>
            </div>
          </div>
        )}

        <button
          onClick={handleLogout}
          title={collapsed ? 'Logout' : undefined}
          className={`
            w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-sm text-slate-400
            hover:text-red-400 hover:bg-red-500/10 transition-all
            ${collapsed ? 'justify-center' : ''}
          `}
        >
          <LogOut size={16} className="shrink-0" />
          {!collapsed && <span>Logout</span>}
        </button>
      </div>

      {/* Collapse toggle */}
      <button
        onClick={() => setCollapsed((c) => !c)}
        className="flex items-center justify-center h-9 border-t border-slate-700/50 text-slate-600 hover:text-slate-300 hover:bg-slate-800 transition-colors"
        title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
      </button>
    </aside>
  )
}

export default Sidebar
