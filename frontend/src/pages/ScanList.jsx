import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Plus,
  Trash2,
  Eye,
  RefreshCw,
  Clock,
  CheckCircle,
  AlertCircle,
  XCircle,
} from 'lucide-react'
import { getScans, createScan, deleteScan } from '../api.js'

const STATUS_ICON = {
  completed: <CheckCircle className="w-3.5 h-3.5 text-green-500" />,
  running: <Clock className="w-3.5 h-3.5 text-blue-500 animate-spin" />,
  failed: <XCircle className="w-3.5 h-3.5 text-red-500" />,
  pending: <AlertCircle className="w-3.5 h-3.5 text-gray-400" />,
}

const STATUS_DOT = {
  completed: 'bg-green-500',
  running: 'bg-blue-500 animate-pulse',
  failed: 'bg-red-500',
  pending: 'bg-gray-400',
}

const STATUS_BADGE = {
  completed: 'bg-green-100 text-green-700',
  running: 'bg-blue-100 text-blue-700',
  failed: 'bg-red-100 text-red-700',
  pending: 'bg-gray-100 text-gray-600',
}

const ScanCard = ({ scan, onDelete, deleteLoading }) => {
  const dotColor = STATUS_DOT[scan.status] || 'bg-gray-400'
  const badgeColor = STATUS_BADGE[scan.status] || 'bg-gray-100 text-gray-600'

  const truncateUrl = (url, maxLen = 40) => {
    if (!url) return ''
    if (url.length <= maxLen) return url
    return url.slice(0, maxLen) + '…'
  }

  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm hover:shadow-md transition-shadow p-5 flex flex-col gap-3">
      {/* Status + URL */}
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className={`w-2 h-2 rounded-full shrink-0 ${dotColor}`} />
            <span className={`text-xs font-semibold px-2 py-0.5 rounded-full capitalize ${badgeColor}`}>
              {scan.status}
            </span>
          </div>
          <p
            className="text-sm font-semibold text-gray-800 truncate"
            title={scan.target_url}
          >
            {truncateUrl(scan.target_url)}
          </p>
        </div>
        <span className="text-xs text-gray-400 shrink-0">#{scan.id}</span>
      </div>

      {/* Date */}
      <div className="flex items-center gap-1.5 text-xs text-gray-400">
        <Clock size={12} />
        {new Date(scan.created_at).toLocaleString()}
      </div>

      {/* Finding count */}
      {scan.status === 'completed' && scan.finding_count !== undefined && scan.finding_count !== null && (
        <div className="flex items-center gap-1.5 text-xs text-gray-600">
          <AlertCircle size={12} className="text-orange-400" />
          <span><span className="font-semibold">{scan.finding_count}</span> finding{scan.finding_count !== 1 ? 's' : ''}</span>
        </div>
      )}

      {/* Running progress bar */}
      {scan.status === 'running' && (
        <div className="w-full bg-blue-100 rounded-full h-1.5 overflow-hidden">
          <div className="bg-blue-500 h-1.5 w-1/2 animate-pulse rounded-full" />
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-2 pt-1 border-t border-gray-100 mt-auto">
        <Link
          to={`/scans/${scan.id}`}
          className="flex-1 flex items-center justify-center gap-1.5 text-xs text-white bg-blue-600 hover:bg-blue-700 py-1.5 rounded-lg transition"
        >
          <Eye size={12} /> View Details
        </Link>
        <button
          onClick={() => onDelete(scan.id)}
          disabled={deleteLoading}
          className="flex items-center gap-1.5 text-xs text-red-500 border border-red-200 hover:bg-red-50 py-1.5 px-3 rounded-lg transition disabled:opacity-50"
        >
          <Trash2 size={12} /> Delete
        </button>
      </div>
    </div>
  )
}

const NewScanModal = ({ onClose, onSubmit, isPending }) => {
  const [targetUrl, setTargetUrl] = useState('')
  const [specUrl, setSpecUrl] = useState('')
  const [specFile, setSpecFile] = useState(null)
  const [specSource, setSpecSource] = useState('url')
  const [authType, setAuthType] = useState('none')
  const [authToken, setAuthToken] = useState('')
  const [basicUser, setBasicUser] = useState('')
  const [basicPass, setBasicPass] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()

    let finalAuthHeader = ''
    if (authType === 'bearer' && authToken) {
      finalAuthHeader = `Bearer ${authToken}`
    } else if (authType === 'basic' && basicUser && basicPass) {
      finalAuthHeader = `Basic ${btoa(`${basicUser}:${basicPass}`)}`
    }

    let specContent = undefined
    if (specSource === 'file' && specFile) {
      try {
        const text = await specFile.text()
        specContent = JSON.parse(text)
      } catch {
        alert('Invalid JSON file')
        return
      }
    }

    onSubmit({
      target_url: targetUrl,
      spec_url: specSource === 'url' ? specUrl : undefined,
      spec_content: specContent,
      config: finalAuthHeader ? { auth_header: finalAuthHeader } : {},
    })
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-2xl shadow-xl w-full max-w-lg">
        {/* Modal header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <h2 className="text-lg font-semibold text-gray-900">New API Scan</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition text-xl leading-none"
          >
            &times;
          </button>
        </div>

        <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4">
          {/* Target URL */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Target URL <span className="text-red-500">*</span>
            </label>
            <input
              type="url"
              required
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent"
              placeholder="https://api.example.com"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
            />
          </div>

          {/* OpenAPI Spec */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              OpenAPI Spec{' '}
              <span className="text-gray-400 font-normal text-xs">(optional — enables deeper checks)</span>
            </label>
            <div className="flex gap-4 mb-2">
              <label className="flex items-center gap-1.5 text-sm cursor-pointer">
                <input
                  type="radio"
                  checked={specSource === 'url'}
                  onChange={() => setSpecSource('url')}
                  className="accent-blue-600"
                />
                URL
              </label>
              <label className="flex items-center gap-1.5 text-sm cursor-pointer">
                <input
                  type="radio"
                  checked={specSource === 'file'}
                  onChange={() => setSpecSource('file')}
                  className="accent-blue-600"
                />
                File Upload
              </label>
            </div>
            {specSource === 'url' ? (
              <input
                key="spec-url"
                type="text"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent"
                placeholder="https://api.example.com/openapi.json"
                value={specUrl}
                onChange={(e) => setSpecUrl(e.target.value)}
              />
            ) : (
              <input
                key="spec-file"
                type="file"
                accept=".json"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
                onChange={(e) => setSpecFile(e.target.files?.[0] || null)}
              />
            )}
          </div>

          {/* Authentication */}
          <div>
            <label htmlFor="scan-auth-type" className="block text-sm font-medium text-gray-700 mb-1">Authentication</label>
            <select
              id="scan-auth-type"
              name="auth_type"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent mb-2"
              value={authType}
              onChange={(e) => setAuthType(e.target.value)}
            >
              <option value="none">No Authentication</option>
              <option value="bearer">Bearer Token</option>
              <option value="basic">Basic Auth (Username / Password)</option>
            </select>

            {authType === 'bearer' && (
              <div>
                <label htmlFor="scan-bearer-token" className="block text-xs text-gray-500 mb-1">Token</label>
                <input
                  id="scan-bearer-token"
                  type="text"
                  name="bearer_token"
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
                  placeholder="eyJhbGciOi..."
                  value={authToken}
                  onChange={(e) => setAuthToken(e.target.value)}
                />
              </div>
            )}

            {authType === 'basic' && (
              <div className="flex gap-2">
                <div className="flex-1">
                  <label htmlFor="scan-basic-username" className="block text-xs text-gray-500 mb-1">Username</label>
                  <input
                    id="scan-basic-username"
                    type="text"
                    name="basic_username"
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
                    placeholder="admin"
                    value={basicUser}
                    onChange={(e) => setBasicUser(e.target.value)}
                  />
                </div>
                <div className="flex-1">
                  <label htmlFor="scan-basic-password" className="block text-xs text-gray-500 mb-1">Password</label>
                  <input
                    id="scan-basic-password"
                    type="password"
                    name="basic_password"
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
                    placeholder="secret"
                    value={basicPass}
                    onChange={(e) => setBasicPass(e.target.value)}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Footer buttons */}
          <div className="flex justify-end gap-2 pt-2 border-t border-gray-100">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-gray-600 hover:bg-gray-100 rounded-lg transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isPending}
              className="px-5 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition disabled:opacity-60 flex items-center gap-1.5"
            >
              {isPending ? (
                <>
                  <RefreshCw size={13} className="animate-spin" /> Starting…
                </>
              ) : (
                <>
                  <Plus size={13} /> Start Scan
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

const ScanList = () => {
  const queryClient = useQueryClient()
  const [isModalOpen, setIsModalOpen] = useState(false)

  const { data: scans, isLoading, error, refetch } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => (await getScans()).data,
  })

  const createMutation = useMutation({
    mutationFn: createScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setIsModalOpen(false)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => deleteScan(id),
    onSuccess: (_data, id) => {
      queryClient.setQueryData(['scans'], (old) => (old ? old.filter((s) => s.id !== id) : old))
    },
    onError: (error) => {
      const message = error?.response?.data?.detail || error?.message || 'Failed to delete scan'
      alert(message)
    },
  })

  const handleDelete = (id) => {
    if (window.confirm('Are you sure you want to delete this scan and all its results?')) {
      deleteMutation.mutate(id)
    }
  }

  const sortedScans = scans
    ? [...scans].sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    : []

  const runningScans = sortedScans.filter((s) => s.status === 'running')

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scans</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Manage and monitor your API security scans
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 px-3 py-2 text-sm text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50 transition"
          >
            <RefreshCw size={14} /> Refresh
          </button>
          <button
            onClick={() => setIsModalOpen(true)}
            className="flex items-center gap-1.5 px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition"
          >
            <Plus size={14} /> New Scan
          </button>
        </div>
      </div>

      {/* Running scan banner */}
      {runningScans.length > 0 && (
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 flex items-center gap-3">
          <Clock className="w-5 h-5 text-blue-500 shrink-0" />
          <div>
            <p className="text-sm font-semibold text-blue-800">
              {runningScans.length} scan{runningScans.length > 1 ? 's' : ''} currently running
            </p>
            <p className="text-xs text-blue-600">
              Checking OWASP API Top 10 vulnerabilities. Refresh to see latest results.
            </p>
          </div>
          <div className="ml-auto w-32 bg-blue-100 rounded-full h-1.5 overflow-hidden shrink-0">
            <div className="bg-blue-500 h-1.5 animate-pulse rounded-full w-1/2" />
          </div>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-sm text-red-700">
          Failed to load scans: {error.message}
          <br />
          <span className="text-xs text-red-400">Ensure the backend is running.</span>
        </div>
      )}

      {/* Loading state */}
      {isLoading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <div key={i} className="h-48 bg-gray-100 animate-pulse rounded-xl" />
          ))}
        </div>
      ) : sortedScans.length === 0 ? (
        /* Empty state */
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-16 flex flex-col items-center justify-center text-center">
          <div className="w-16 h-16 bg-blue-50 rounded-full flex items-center justify-center mb-4">
            <Plus className="w-7 h-7 text-blue-400" />
          </div>
          <h3 className="text-lg font-semibold text-gray-800 mb-1">No scans yet</h3>
          <p className="text-sm text-gray-400 mb-5 max-w-xs">
            Start your first API security scan to discover vulnerabilities and check OWASP API Top 10 coverage.
          </p>
          <button
            onClick={() => setIsModalOpen(true)}
            className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 transition"
          >
            <Plus size={14} /> Start Your First Scan
          </button>
        </div>
      ) : (
        /* Scan grid */
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {sortedScans.map((scan) => (
            <ScanCard
              key={scan.id}
              scan={scan}
              onDelete={handleDelete}
              deleteLoading={deleteMutation.isPending}
            />
          ))}
        </div>
      )}

      {/* New Scan Modal */}
      {isModalOpen && (
        <NewScanModal
          onClose={() => setIsModalOpen(false)}
          onSubmit={(data) => createMutation.mutate(data)}
          isPending={createMutation.isPending}
        />
      )}
    </div>
  )
}

export default ScanList
