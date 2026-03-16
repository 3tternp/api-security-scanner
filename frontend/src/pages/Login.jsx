import { useState } from 'react'
import { Shield, Lock, Mail, Eye, EyeOff, AlertCircle } from 'lucide-react'
import { login } from '../api.js'

const OWASP_TAGS = ['API1', 'API2', 'API3', 'API4', 'API5', 'API6', 'API7', 'API8', 'API9', 'API10']

const Login = ({ setIsAuthenticated }) => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const response = await login(email, password)
      localStorage.setItem('token', response.data.access_token)
      setIsAuthenticated(true)
    } catch {
      setError('Invalid email or password. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col">

      {/* Top bar */}
      <div className="border-b border-slate-800 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-md flex items-center justify-center">
            <Shield size={14} className="text-white" />
          </div>
          <span className="text-sm font-bold text-white tracking-tight">API Vulnerability Scanner</span>
        </div>
        <div className="flex items-center gap-2">
          {OWASP_TAGS.map((tag) => (
            <span
              key={tag}
              className="text-[9px] font-mono font-semibold px-1.5 py-0.5 rounded border border-slate-700 text-slate-500"
            >
              {tag}
            </span>
          ))}
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 flex items-center justify-center px-4 py-12">
        <div className="w-full max-w-sm">

          {/* Header */}
          <div className="text-center mb-8">
            <div className="inline-flex w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 items-center justify-center shadow-2xl shadow-cyan-500/30 mb-4">
              <Shield size={28} className="text-white" />
            </div>
            <h1 className="text-2xl font-black text-white">Secure Access</h1>
            <p className="text-sm text-slate-400 mt-1">
              OWASP API Security Top 10 · 2023
            </p>
            <div className="flex items-center justify-center gap-1.5 mt-3">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs text-emerald-400 font-medium">Scanner Online</span>
            </div>
          </div>

          {/* Card */}
          <div className="bg-slate-900 border border-slate-700/60 rounded-2xl p-7 shadow-2xl shadow-black/50">

            {/* Error */}
            {error && (
              <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3 mb-5">
                <AlertCircle size={14} className="text-red-400 shrink-0" />
                <span className="text-sm text-red-400">{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Email */}
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1.5">
                  Email Address
                </label>
                <div className="relative">
                  <Mail size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                  <input
                    type="email"
                    required
                    autoComplete="email"
                    placeholder="admin@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded-xl pl-10 pr-4 py-3 text-sm text-white placeholder-slate-500
                      focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50 transition"
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1.5">
                  Password
                </label>
                <div className="relative">
                  <Lock size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    autoComplete="current-password"
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded-xl pl-10 pr-11 py-3 text-sm text-white placeholder-slate-500
                      focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50 transition"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((v) => !v)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition"
                    tabIndex={-1}
                  >
                    {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>

              {/* Submit */}
              <button
                type="submit"
                disabled={loading}
                className="w-full mt-2 py-3 rounded-xl text-sm font-bold text-white
                  bg-gradient-to-r from-cyan-500 to-blue-600
                  hover:from-cyan-400 hover:to-blue-500
                  disabled:opacity-60 disabled:cursor-not-allowed
                  shadow-lg shadow-cyan-500/20
                  transition-all duration-150
                  flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Authenticating…
                  </>
                ) : (
                  <>
                    <Shield size={15} />
                    Sign In
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Footer note */}
          <p className="text-center text-xs text-slate-600 mt-6">
            Protected by JWT · Role-based access control
          </p>
        </div>
      </div>

      {/* Bottom grid decoration */}
      <div className="border-t border-slate-800 px-6 py-4">
        <div className="grid grid-cols-10 gap-1.5 max-w-xl mx-auto">
          {OWASP_TAGS.map((tag, i) => (
            <div
              key={tag}
              className="flex flex-col items-center gap-0.5 p-1.5 rounded-lg border border-slate-800 bg-slate-900/50"
            >
              <span className="text-[8px] font-black text-slate-500">{tag}</span>
              <div
                className="w-1 h-1 rounded-full"
                style={{ background: `hsl(${200 + i * 16}, 70%, 50%)`, opacity: 0.5 }}
              />
            </div>
          ))}
        </div>
        <p className="text-center text-[10px] text-slate-700 mt-2 uppercase tracking-widest">
          OWASP API Security Top 10 — 2023
        </p>
      </div>
    </div>
  )
}

export default Login
