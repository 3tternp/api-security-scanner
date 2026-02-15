import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { getScans, createScan, getScanResults, deleteScan } from '../api.js'
import { Play, Eye, Trash2 } from 'lucide-react'

const ScanList = () => {
  const queryClient = useQueryClient()
  const [targetUrl, setTargetUrl] = useState('')
  const [specUrl, setSpecUrl] = useState('')
  const [specFile, setSpecFile] = useState(null)
  const [specSource, setSpecSource] = useState('url')
  const [authType, setAuthType] = useState('none')
  const [authToken, setAuthToken] = useState('')
  const [basicUser, setBasicUser] = useState('')
  const [basicPass, setBasicPass] = useState('')
  const [isModalOpen, setIsModalOpen] = useState(false)

  const { data: scans, isLoading, error } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const res = await getScans()
      return res.data
    },
  })

  const completedScans = (scans || []).filter((s) => s.status === 'completed')
  completedScans.sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
  )
  const latestCompleted = completedScans.length > 0 ? completedScans[0] : null

  const {
    data: latestResults,
    isLoading: owaspLoading,
  } = useQuery({
    queryKey: ['scan-results-summary', latestCompleted?.id],
    queryFn: async () => {
      if (!latestCompleted) return []
      const res = await getScanResults(latestCompleted.id)
      return res.data
    },
    enabled: !!latestCompleted,
  })

  const mutation = useMutation({
    mutationFn: createScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setIsModalOpen(false)
      setTargetUrl('')
      setSpecUrl('')
      setSpecFile(null)
      setSpecSource('url')
      setAuthToken('')
      setBasicUser('')
      setBasicPass('')
      setAuthType('none')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => deleteScan(id),
    onSuccess: (_data, id) => {
      queryClient.setQueryData(['scans'], (old) => {
        if (!old) return old
        return old.filter((scan) => scan.id !== id)
      })
    },
    onError: (error) => {
      const message =
        error?.response?.data?.detail || error?.message || 'Failed to delete scan'
      alert(message)
    },
  })

  const handleDelete = (id) => {
    const confirmed = window.confirm('Are you sure you want to delete this scan and its results?')
    if (!confirmed) return
    deleteMutation.mutate(id)
  }

  const handleStartScan = async (e) => {
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
      } catch (err) {
        alert('Invalid JSON file')
        return
      }
    }

    mutation.mutate({
      target_url: targetUrl,
      spec_url: specSource === 'url' ? specUrl : undefined,
      spec_content: specContent,
      config: finalAuthHeader ? { auth_header: finalAuthHeader } : {},
    })
  }

  if (isLoading) return <div>Loading...</div>
  if (error)
    return (
      <div className="p-4 text-red-600 bg-red-50 rounded">
        Error loading scans: {error.message}
        <br />
        <span className="text-xs text-gray-500">
          Check console for details. Ensure backend is running.
        </span>
      </div>
    )

  return (
    <div className="space-y-6">
      {scans && scans.some((s) => s.status === 'running') && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex justify-between items-center mb-2">
            <div>
              <p className="text-sm font-semibold text-blue-800">
                Scan in progress – checking OWASP API Top 10
              </p>
              <p className="text-xs text-blue-700">
                The engine is running all enabled OWASP API Top 10 checks against your target.
              </p>
            </div>
          </div>
          <div className="w-full bg-blue-100 rounded-full h-2 mt-2 overflow-hidden">
            <div className="bg-blue-500 h-2 w-1/2 animate-pulse" />
          </div>
        </div>
      )}

      <div className="flex justify-between items-start gap-4">
        <div>
          <h1 className="text-2xl font-bold mb-1">Dashboard</h1>
          <p className="text-sm text-gray-600">
            Track API scans and OWASP API Top 10 coverage.
          </p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded flex items-center gap-2 hover:bg-blue-700"
        >
          <Play size={16} /> New Scan
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <div className="bg-white rounded-lg shadow overflow-hidden">
            <table className="min-w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    ID
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Target
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Created At
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {scans?.map((scan) => (
                  <tr key={scan.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      #{scan.id}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                      {scan.target_url}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <span
                        className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                        ${
                          scan.status === 'completed'
                            ? 'bg-green-100 text-green-800'
                            : scan.status === 'running'
                            ? 'bg-yellow-100 text-yellow-800'
                            : scan.status === 'failed'
                            ? 'bg-red-100 text-red-800'
                            : 'bg-gray-100 text-gray-800'
                        }`}
                      >
                        {scan.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex items-center gap-3">
                        <Link
                          to={`/scans/${scan.id}`}
                          className="text-blue-600 hover:text-blue-900 flex items-center gap-1"
                        >
                          <Eye size={16} /> View
                        </Link>
                        <button
                          type="button"
                          onClick={() => handleDelete(scan.id)}
                          className="text-red-600 hover:text-red-800 flex items-center gap-1 text-xs disabled:opacity-50"
                          disabled={deleteMutation.isPending}
                        >
                          <Trash2 size={14} /> Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-4">
          <h2 className="text-lg font-semibold mb-2">OWASP API Top 10</h2>
          <p className="text-xs text-gray-600 mb-3">
            Latest completed scan OWASP coverage.
          </p>

          {owaspLoading && latestCompleted && (
            <p className="text-xs text-gray-500">Loading OWASP status…</p>
          )}

          {!latestCompleted && (
            <p className="text-xs text-gray-500">
              Run a scan to see OWASP API Top 10 status here.
            </p>
          )}

          {latestCompleted && latestResults && latestResults.length > 0 && (
            <div className="space-y-1 text-xs text-gray-800">
              {[
                { id: 'API1', name: 'Broken Object Level Authorization' },
                { id: 'API2', name: 'Broken Authentication' },
                { id: 'API3', name: 'Broken Object Property Level Authorization' },
                { id: 'API4', name: 'Unrestricted Resource Consumption' },
                { id: 'API5', name: 'Broken Function Level Authorization' },
                { id: 'API6', name: 'Unrestricted Access to Sensitive Business Flows' },
                { id: 'API7', name: 'Server Side Request Forgery' },
                { id: 'API8', name: 'Security Misconfiguration' },
                { id: 'API9', name: 'Improper Inventory Management' },
                { id: 'API10', name: 'Unsafe Consumption of APIs' },
              ].map((item) => {
                const found = latestResults.some((r) => {
                  const details = r.details && typeof r.details === 'object' ? r.details : null
                  const owaspTag =
                    details && typeof details.owasp === 'string' ? details.owasp : undefined
                  return owaspTag ? owaspTag.includes(item.id) : false
                })

                return (
                  <div key={item.id} className="flex justify-between items-center">
                    <span>
                      <span className="font-semibold">{item.id}</span> – {item.name}
                    </span>
                    <span
                      className={`ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                        found
                          ? 'bg-red-100 text-red-700'
                          : 'bg-green-100 text-green-700'
                      }`}
                    >
                      {found ? 'FOUND' : 'NOT FOUND'}
                    </span>
                  </div>
                )
              })}
              <p className="text-[10px] text-gray-500 mt-2">
                Based on latest completed scan (ID #{latestCompleted.id}).
              </p>
            </div>
          )}
        </div>
      </div>

      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-bold mb-4">Start New Scan</h2>
            <form onSubmit={handleStartScan}>
              <div className="mb-4">
                <label className="block text-sm font-medium mb-1">Target URL</label>
                <input
                  type="url"
                  required
                  className="w-full border rounded p-2"
                  placeholder="https://api.example.com"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                />
              </div>
              <div className="mb-4">
                <label className="block text-sm font-medium mb-1">
                  OpenAPI Spec Source{' '}
                  <span className="text-gray-500 font-normal">(Required for detailed checks)</span>
                </label>
                <div className="flex gap-4 mb-2">
                  <label className="flex items-center">
                    <input
                      type="radio"
                      className="mr-2"
                      checked={specSource === 'url'}
                      onChange={() => setSpecSource('url')}
                    />
                    URL
                  </label>
                  <label className="flex items-center">
                    <input
                      type="radio"
                      className="mr-2"
                      checked={specSource === 'file'}
                      onChange={() => setSpecSource('file')}
                    />
                    File Upload
                  </label>
                </div>

                {specSource === 'url' ? (
                  <input
                    key="spec-url-input"
                    type="text"
                    className="w-full border rounded p-2"
                    placeholder="https://api.example.com/openapi.json"
                    value={specUrl}
                    onChange={(e) => setSpecUrl(e.target.value)}
                  />
                ) : (
                  <input
                    key="spec-file-input"
                    type="file"
                    accept=".json"
                    className="w-full border rounded p-2"
                    onChange={(e) => setSpecFile(e.target.files?.[0] || null)}
                  />
                )}
                <p className="text-xs text-gray-500 mt-1">
                  Provide this to enable Auth, PII, and Logic checks.
                </p>
              </div>
              <div className="mb-6">
                <label className="block text-sm font-medium mb-1">Authentication</label>
                <select
                  className="w-full border rounded p-2 mb-3"
                  value={authType}
                  onChange={(e) => setAuthType(e.target.value)}
                >
                  <option value="none">No Authentication</option>
                  <option value="bearer">Bearer Token</option>
                  <option value="basic">Basic Auth (Username/Password)</option>
                </select>

                {authType === 'bearer' && (
                  <div>
                    <label className="block text-xs text-gray-500 mb-1">Token</label>
                    <input
                      type="text"
                      className="w-full border rounded p-2"
                      placeholder="e.g. eyJhbGciOi..."
                      value={authToken}
                      onChange={(e) => setAuthToken(e.target.value)}
                    />
                  </div>
                )}

                {authType === 'basic' && (
                  <div className="flex gap-2">
                    <div className="flex-1">
                      <label className="block text-xs text-gray-500 mb-1">Username</label>
                      <input
                        type="text"
                        className="w-full border rounded p-2"
                        placeholder="admin"
                        value={basicUser}
                        onChange={(e) => setBasicUser(e.target.value)}
                      />
                    </div>
                    <div className="flex-1">
                      <label className="block text-xs text-gray-500 mb-1">Password</label>
                      <input
                        type="password"
                        className="w-full border rounded p-2"
                        placeholder="secret"
                        value={basicPass}
                        onChange={(e) => setBasicPass(e.target.value)}
                      />
                    </div>
                  </div>
                )}
              </div>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 text-gray-600 hover:bg-gray-100 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                  disabled={mutation.isPending}
                >
                  {mutation.isPending ? 'Starting...' : 'Start Scan'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

export default ScanList
