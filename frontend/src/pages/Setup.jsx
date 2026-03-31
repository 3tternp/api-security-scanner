import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff, CheckCircle, AlertCircle, Lock, Mail, User } from 'lucide-react'
import api from '../api'

const PASSWORD_RULES = [
  { test: (p) => p.length >= 12,          label: '12+ characters' },
  { test: (p) => /[A-Z]/.test(p),         label: 'Uppercase letter' },
  { test: (p) => /[a-z]/.test(p),         label: 'Lowercase letter' },
  { test: (p) => /\d/.test(p),            label: 'Number' },
  { test: (p) => /[!@#$%^&*()\-_=+\[\]{};:'",.<>?/\\|`~]/.test(p), label: 'Special character' },
]

function PasswordStrength({ password }) {
  const passed = PASSWORD_RULES.filter((r) => r.test(password)).length
  const pct = (passed / PASSWORD_RULES.length) * 100
  const color = pct <= 40 ? 'bg-red-500' : pct <= 70 ? 'bg-yellow-500' : 'bg-emerald-500'
  const label = pct <= 40 ? 'Weak' : pct <= 70 ? 'Fair' : pct < 100 ? 'Good' : 'Strong'

  return (
    <div className="mt-2 space-y-2">
      <div className="flex items-center gap-2">
        <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
          <div className={`h-full rounded-full transition-all duration-300 ${color}`} style={{ width: `${pct}%` }} />
        </div>
        <span className="text-xs text-slate-400">{password ? label : ''}</span>
      </div>
      <div className="grid grid-cols-2 gap-1">
        {PASSWORD_RULES.map((rule) => {
          const ok = rule.test(password)
          return (
            <div key={rule.label} className={`flex items-center gap-1 text-xs ${ok ? 'text-emerald-400' : 'text-slate-500'}`}>
              <CheckCircle className="w-3 h-3" />
              {rule.label}
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default function Setup({ onSetupComplete }) {
  const navigate = useNavigate()
  const [form, setForm] = useState({ email: '', password: '', confirmPassword: '', fullName: '' })
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)

  const allRulesMet = PASSWORD_RULES.every((r) => r.test(form.password))
  const passwordsMatch = form.password === form.confirmPassword
  const canSubmit = form.email && allRulesMet && passwordsMatch && !loading

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!canSubmit) return
    setLoading(true)
    setError('')
    try {
      await api.post('/setup/', {
        email: form.email,
        password: form.password,
        full_name: form.fullName || undefined,
      })
      setSuccess(true)
      setTimeout(() => {
        onSetupComplete?.()
        navigate('/login')
      }, 2000)
    } catch (err) {
      setError(err.response?.data?.detail || 'Setup failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      {/* Background grid */}
      <div className="fixed inset-0 opacity-5 pointer-events-none"
        style={{ backgroundImage: 'linear-gradient(rgba(6,182,212,0.3) 1px,transparent 1px),linear-gradient(90deg,rgba(6,182,212,0.3) 1px,transparent 1px)', backgroundSize: '40px 40px' }} />

      <div className="w-full max-w-md relative z-10">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 mb-4 shadow-lg shadow-cyan-500/30">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">Initial Setup</h1>
          <p className="text-slate-400 text-sm mt-1">Create your administrator account to get started</p>
        </div>

        {/* Card */}
        <div className="bg-slate-900 border border-slate-700/50 rounded-2xl p-8 shadow-2xl">
          {success ? (
            <div className="text-center py-6">
              <CheckCircle className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
              <p className="text-white font-semibold">Admin account created!</p>
              <p className="text-slate-400 text-sm mt-1">Redirecting to login…</p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-5">
              {/* Full name */}
              <div>
                <label htmlFor="setup-full-name" className="block text-sm font-medium text-slate-300 mb-1.5">
                  Full Name <span className="text-slate-500">(optional)</span>
                </label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                  <input
                    id="setup-full-name"
                    type="text"
                    name="full_name"
                    value={form.fullName}
                    onChange={(e) => setForm({ ...form, fullName: e.target.value })}
                    placeholder="Jane Smith"
                    className="w-full bg-slate-800 border border-slate-600 rounded-lg pl-10 pr-4 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50 text-sm"
                  />
                </div>
              </div>

              {/* Email */}
              <div>
                <label htmlFor="setup-email" className="block text-sm font-medium text-slate-300 mb-1.5">
                  Admin Email <span className="text-red-400">*</span>
                </label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                  <input
                    id="setup-email"
                    type="email"
                    name="email"
                    value={form.email}
                    onChange={(e) => setForm({ ...form, email: e.target.value })}
                    placeholder="admin@company.com"
                    required
                    className="w-full bg-slate-800 border border-slate-600 rounded-lg pl-10 pr-4 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50 text-sm"
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <label htmlFor="setup-password" className="block text-sm font-medium text-slate-300 mb-1.5">
                  Password <span className="text-red-400">*</span>
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                  <input
                    id="setup-password"
                    type={showPassword ? 'text' : 'password'}
                    name="password"
                    value={form.password}
                    onChange={(e) => setForm({ ...form, password: e.target.value })}
                    placeholder="Min 12 chars, upper/lower/digit/special"
                    required
                    className="w-full bg-slate-800 border border-slate-600 rounded-lg pl-10 pr-10 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50 text-sm"
                  />
                  <button type="button" onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {form.password && <PasswordStrength password={form.password} />}
              </div>

              {/* Confirm password */}
              <div>
                <label htmlFor="setup-confirm-password" className="block text-sm font-medium text-slate-300 mb-1.5">
                  Confirm Password <span className="text-red-400">*</span>
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                  <input
                    id="setup-confirm-password"
                    type={showPassword ? 'text' : 'password'}
                    name="confirm_password"
                    value={form.confirmPassword}
                    onChange={(e) => setForm({ ...form, confirmPassword: e.target.value })}
                    placeholder="Repeat your password"
                    required
                    className={`w-full bg-slate-800 border rounded-lg pl-10 pr-4 py-2.5 text-white placeholder-slate-500 focus:outline-none text-sm ${
                      form.confirmPassword && !passwordsMatch ? 'border-red-500 focus:border-red-500' : 'border-slate-600 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50'
                    }`}
                  />
                </div>
                {form.confirmPassword && !passwordsMatch && (
                  <p className="text-red-400 text-xs mt-1 flex items-center gap-1">
                    <AlertCircle className="w-3 h-3" /> Passwords do not match
                  </p>
                )}
              </div>

              {/* Error */}
              {error && (
                <div className="bg-red-900/30 border border-red-500/50 rounded-lg p-3 flex items-start gap-2">
                  <AlertCircle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                  <p className="text-red-300 text-sm">{error}</p>
                </div>
              )}

              {/* Submit */}
              <button
                type="submit"
                disabled={!canSubmit}
                className="w-full py-3 rounded-lg font-semibold text-sm bg-gradient-to-r from-cyan-500 to-blue-600 text-white hover:from-cyan-400 hover:to-blue-500 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200 shadow-lg shadow-cyan-500/25"
              >
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                    </svg>
                    Creating account…
                  </span>
                ) : 'Create Admin Account'}
              </button>
            </form>
          )}
        </div>

        <p className="text-center text-slate-600 text-xs mt-6">
          This page is only accessible before any admin account exists.
        </p>
      </div>
    </div>
  )
}
