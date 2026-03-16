import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  AlertOctagon,
  Shield,
  Download,
  FileText,
  Filter,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  CheckCircle,
  Clock,
  XCircle,
} from 'lucide-react'
import jsPDF from 'jspdf'
import autoTable from 'jspdf-autotable'
import { getScan, getScanResults, updateFindingStatus, downloadDocxReport } from '../api.js'

const SEVERITY = {
  critical: {
    label: 'Critical',
    border: 'border-red-600',
    bg: 'bg-red-50',
    badge: 'bg-red-100 text-red-700',
    icon: 'text-red-700',
    dot: 'bg-red-600',
  },
  high: {
    label: 'High',
    border: 'border-orange-500',
    bg: 'bg-orange-50',
    badge: 'bg-orange-100 text-orange-600',
    icon: 'text-orange-600',
    dot: 'bg-orange-500',
  },
  medium: {
    label: 'Medium',
    border: 'border-yellow-500',
    bg: 'bg-yellow-50',
    badge: 'bg-yellow-100 text-yellow-600',
    icon: 'text-yellow-600',
    dot: 'bg-yellow-400',
  },
  low: {
    label: 'Low',
    border: 'border-blue-500',
    bg: 'bg-blue-50',
    badge: 'bg-blue-100 text-blue-600',
    icon: 'text-blue-600',
    dot: 'bg-blue-400',
  },
  info: {
    label: 'Info',
    border: 'border-gray-400',
    bg: 'bg-gray-50',
    badge: 'bg-gray-100 text-gray-500',
    icon: 'text-gray-500',
    dot: 'bg-gray-400',
  },
}

const STATUS_OPTIONS = ['Open', 'In Progress', 'Fixed', 'Accepted Risk']

const getSeverityConfig = (severity) =>
  SEVERITY[(severity || '').toLowerCase()] || SEVERITY.info

const SeveritySummaryCard = ({ label, count, config }) => (
  <div className={`rounded-lg border-l-4 ${config.border} ${config.bg} p-4 text-center`}>
    <p className={`text-2xl font-bold ${config.icon}`}>{count}</p>
    <p className="text-xs text-gray-600 mt-0.5">{label}</p>
  </div>
)

const FindingCard = ({ result, onStatusChange }) => {
  const [expanded, setExpanded] = useState(false)
  const cfg = getSeverityConfig(result.severity)

  return (
    <div className={`rounded-xl border border-gray-200 border-l-4 ${cfg.border} bg-white shadow-sm overflow-hidden`}>
      <div className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 min-w-0">
            <AlertOctagon className={`w-5 h-5 mt-0.5 shrink-0 ${cfg.icon}`} />
            <div className="min-w-0">
              <h3 className="font-semibold text-gray-900 text-sm leading-tight">
                <span className="font-mono text-xs text-gray-500 mr-1">{result.rule_id}</span>
                {result.description}
              </h3>
              <div className="mt-1.5 flex flex-wrap items-center gap-2">
                {result.method && (
                  <span className="font-mono text-xs bg-gray-100 text-gray-700 px-1.5 py-0.5 rounded">
                    {result.method}
                  </span>
                )}
                {result.endpoint && (
                  <span className="font-mono text-xs text-gray-600 truncate max-w-xs">
                    {result.endpoint}
                  </span>
                )}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${cfg.badge}`}>
              {cfg.label}
            </span>
            <select
              className="text-xs border border-gray-200 rounded-md px-2 py-1 bg-white text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-300"
              value={result.status || 'Open'}
              onChange={(e) => onStatusChange(result.id, e.target.value)}
            >
              {STATUS_OPTIONS.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <button
              onClick={() => setExpanded((v) => !v)}
              className="text-gray-400 hover:text-gray-600 transition p-1"
              title={expanded ? 'Collapse' : 'Expand'}
            >
              {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            </button>
          </div>
        </div>
      </div>

      {expanded && (
        <div className="border-t border-gray-100 px-4 py-4 space-y-4 bg-gray-50">
          {/* CVSS */}
          {(result.cvss_score || result.cvss_vector) && (
            <div className="flex flex-wrap gap-4">
              {result.cvss_score !== undefined && result.cvss_score !== null && (
                <div>
                  <p className="text-xs font-semibold text-gray-500 uppercase mb-0.5">CVSS Score</p>
                  <span className={`text-sm font-bold ${cfg.icon}`}>{result.cvss_score}</span>
                </div>
              )}
              {result.cvss_vector && (
                <div>
                  <p className="text-xs font-semibold text-gray-500 uppercase mb-0.5">CVSS Vector</p>
                  <span className="text-xs font-mono text-gray-700">{result.cvss_vector}</span>
                </div>
              )}
            </div>
          )}

          {/* Impact */}
          {result.impact && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase mb-1">Impact</p>
              <p className="text-sm text-gray-700">{result.impact}</p>
            </div>
          )}

          {/* Remediation */}
          {result.remediation && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase mb-1">Remediation</p>
              <p className="text-sm text-gray-700">{result.remediation}</p>
            </div>
          )}

          {/* Proof of Concept */}
          {result.proof_of_concept && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase mb-1">Proof of Concept</p>
              <pre className="text-xs font-mono bg-white border border-gray-200 rounded p-3 whitespace-pre-wrap overflow-x-auto text-gray-800">
                {result.proof_of_concept}
              </pre>
            </div>
          )}

          {/* Technical Details */}
          {result.details && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase mb-1">Technical Details</p>
              <pre className="text-xs font-mono bg-white border border-gray-200 rounded p-3 whitespace-pre-wrap overflow-x-auto text-gray-800">
                {JSON.stringify(result.details, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

const ScanDetail = () => {
  const { id } = useParams()
  const queryClient = useQueryClient()
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ['scan', id],
    queryFn: async () => (await getScan(id)).data,
    enabled: !!id,
  })

  const { data: results, isLoading: resultsLoading, refetch: refetchResults } = useQuery({
    queryKey: ['scan-results', id],
    queryFn: async () => (await getScanResults(id)).data,
    enabled: !!id,
  })

  const statusMutation = useMutation({
    mutationFn: ({ resultId, status }) => updateFindingStatus(resultId, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan-results', id] })
    },
    onError: () => {
      alert('Failed to update finding status')
    },
  })

  const handleStatusChange = (resultId, status) => {
    statusMutation.mutate({ resultId, status })
  }

  const handleDocxDownload = async () => {
    try {
      const response = await downloadDocxReport(id)
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `scan_report_${id}.docx`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch (e) {
      alert('Failed to download DOCX report')
    }
  }

  const exportPDF = () => {
    if (!scan || !results) return

    const doc = new jsPDF()

    doc.setFontSize(20)
    doc.text('API Vulnerability Scan Report', 14, 20)

    doc.setFontSize(10)
    doc.text(`Target URL: ${scan.target_url}`, 14, 30)
    doc.text(`Scan Date: ${new Date(scan.created_at).toLocaleString()}`, 14, 35)
    doc.text(`Total Findings: ${results.length}`, 14, 40)

    let yPos = 50

    const owaspItems = [
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
    ]

    const owaspSummary = owaspItems.map((item) => {
      const found = results.some((r) => {
        const details = r.details && typeof r.details === 'object' ? r.details : null
        const owaspTag = details && typeof details.owasp === 'string' ? details.owasp : undefined
        return owaspTag ? owaspTag.includes(item.id) : false
      })
      return { id: item.id, name: item.name, status: found ? 'FOUND' : 'NOT FOUND' }
    })

    autoTable(doc, {
      startY: yPos,
      head: [['OWASP API Top 10', 'Status']],
      body: owaspSummary.map((row) => [`${row.id} ${row.name}`, row.status]),
      theme: 'grid',
      styles: { fontSize: 9, cellPadding: 2 },
      columnStyles: { 0: { cellWidth: 110 } },
      margin: { left: 14, right: 14 },
    })

    yPos = doc.lastAutoTable.finalY + 15

    const groupedMap = new Map()

    results.forEach((result) => {
      const key = `${result.rule_id}|${result.description}|${result.severity}|${result.impact}|${result.remediation}`
      const endpointStr = `${result.method} ${result.endpoint}`
      const existing = groupedMap.get(key)

      if (!existing) {
        groupedMap.set(key, {
          base: result,
          endpoints: [endpointStr],
          proofs: result.proof_of_concept ? [result.proof_of_concept] : [],
        })
      } else {
        if (!existing.endpoints.includes(endpointStr)) existing.endpoints.push(endpointStr)
        if (result.proof_of_concept && !existing.proofs.includes(result.proof_of_concept)) {
          existing.proofs.push(result.proof_of_concept)
        }
      }
    })

    const groupedResults = Array.from(groupedMap.values())

    groupedResults.forEach(({ base, endpoints, proofs }, index) => {
      if (yPos > 250) {
        doc.addPage()
        yPos = 20
      }

      doc.setFontSize(14)
      doc.setTextColor(200, 0, 0)
      doc.text(`Issue #${index + 1}: ${base.rule_id}`, 14, yPos)
      yPos += 7

      doc.setFontSize(10)
      doc.setTextColor(0, 0, 0)

      let affectedIPs = ''
      let port = ''
      try {
        const urlObj = new URL(scan.target_url)
        port = urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80')
        affectedIPs = urlObj.hostname
      } catch (_) {
        affectedIPs = scan.target_url
        port = '443'
      }

      const endpointsText = endpoints.join('\n')
      const proofText = proofs.length > 0 ? proofs.join('\n\n') : 'See details.'
      const explanation =
        base.details &&
        typeof base.details === 'object' &&
        typeof base.details.explanation === 'string'
          ? base.details.explanation
          : base.description

      const data = [
        ['Issue Name', base.description],
        ['Affected IPs', affectedIPs],
        ['Endpoints', endpointsText],
        ['Method used', 'OWASP API Scanner'],
        ['Port Used', port],
        ['Vulnerability details', explanation],
        ['Attack Vector', base.attack_vector || 'Network'],
        ['Attack Complexity', base.attack_complexity || 'Low'],
        ['Privileges Required', base.privileges_required || 'None'],
        ['User Interaction', base.user_interaction || 'None'],
        ['Scope', base.scope || 'Unchanged'],
        ['Confidentiality', base.confidentiality || 'None'],
        ['Integrity', base.integrity || 'None'],
        ['Availability', base.availability || 'None'],
        ['Severity-Rating', (base.severity || '').toUpperCase()],
        ['Business impact', base.impact || 'Unknown'],
        ['Remediation', base.remediation || 'See OWASP guidelines.'],
        ['Proof of Concept', proofText],
      ]

      autoTable(doc, {
        startY: yPos,
        head: [],
        body: data,
        theme: 'grid',
        styles: { fontSize: 9, cellPadding: 2 },
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 50 } },
        margin: { left: 14, right: 14 },
      })

      yPos = doc.lastAutoTable.finalY + 15
    })

    doc.save(`scan_report_${id}.pdf`)
  }

  // Severity counts
  const severityCounts = results
    ? ['critical', 'high', 'medium', 'low', 'info'].reduce((acc, s) => {
        acc[s] = results.filter((r) => (r.severity || '').toLowerCase() === s).length
        return acc
      }, {})
    : {}

  // Filtered results
  const filteredResults = (results || []).filter((r) => {
    const sev = (r.severity || '').toLowerCase()
    const st = r.status || 'Open'
    const sevMatch = severityFilter === 'all' || sev === severityFilter
    const stMatch = statusFilter === 'all' || st === statusFilter
    return sevMatch && stMatch
  })

  const isLoading = scanLoading || resultsLoading

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Link to="/scans" className="text-sm text-gray-400 hover:text-gray-600">Scans</Link>
            <span className="text-gray-300">/</span>
            <span className="text-sm text-gray-600">Scan #{id}</span>
          </div>
          {scanLoading ? (
            <div className="space-y-2">
              <div className="h-6 w-64 bg-gray-200 animate-pulse rounded" />
              <div className="h-4 w-40 bg-gray-100 animate-pulse rounded" />
            </div>
          ) : (
            <>
              <h1 className="text-xl font-bold text-gray-900 truncate max-w-lg">
                {scan?.target_url || `Scan #${id}`}
              </h1>
              <div className="flex items-center gap-3 mt-1 flex-wrap">
                <span
                  className={`text-xs font-semibold px-2 py-0.5 rounded-full capitalize ${
                    scan?.status === 'completed'
                      ? 'bg-green-100 text-green-700'
                      : scan?.status === 'running'
                      ? 'bg-blue-100 text-blue-700'
                      : scan?.status === 'failed'
                      ? 'bg-red-100 text-red-700'
                      : 'bg-gray-100 text-gray-600'
                  }`}
                >
                  {scan?.status}
                </span>
                {scan?.created_at && (
                  <span className="text-xs text-gray-400">
                    {new Date(scan.created_at).toLocaleString()}
                  </span>
                )}
                {results && (
                  <span className="text-xs text-gray-400">
                    {results.length} total finding{results.length !== 1 ? 's' : ''}
                  </span>
                )}
              </div>
            </>
          )}
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => refetchResults()}
            className="flex items-center gap-1.5 px-3 py-2 text-sm text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50 transition"
          >
            <RefreshCw size={14} /> Refresh
          </button>
          <button
            onClick={exportPDF}
            disabled={!scan || !results}
            className="flex items-center gap-1.5 px-3 py-2 text-sm text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition disabled:opacity-40"
          >
            <Download size={14} /> Export PDF
          </button>
          <button
            onClick={handleDocxDownload}
            className="flex items-center gap-1.5 px-3 py-2 text-sm text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg transition"
          >
            <FileText size={14} /> Download DOCX
          </button>
        </div>
      </div>

      {/* Severity Summary Cards */}
      {isLoading ? (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="h-20 bg-gray-100 animate-pulse rounded-lg" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
            <SeveritySummaryCard
              key={s}
              label={SEVERITY[s].label}
              count={severityCounts[s] || 0}
              config={SEVERITY[s]}
            />
          ))}
        </div>
      )}

      {/* Filter Bar */}
      <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-4">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-1.5 text-sm text-gray-500">
            <Filter size={14} />
            <span className="font-medium">Filter:</span>
          </div>

          <div className="flex items-center gap-1 flex-wrap">
            <span className="text-xs text-gray-400 mr-1">Severity:</span>
            {['all', 'critical', 'high', 'medium', 'low', 'info'].map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                className={`text-xs px-2.5 py-1 rounded-full font-medium transition ${
                  severityFilter === s
                    ? 'bg-gray-800 text-white'
                    : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                }`}
              >
                {s === 'all' ? 'All' : SEVERITY[s].label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 flex-wrap">
            <span className="text-xs text-gray-400 mr-1">Status:</span>
            {['all', ...STATUS_OPTIONS].map((s) => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={`text-xs px-2.5 py-1 rounded-full font-medium transition ${
                  statusFilter === s
                    ? 'bg-gray-800 text-white'
                    : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                }`}
              >
                {s === 'all' ? 'All' : s}
              </button>
            ))}
          </div>

          {results && (
            <span className="ml-auto text-xs text-gray-400">
              {filteredResults.length} of {results.length} findings
            </span>
          )}
        </div>
      </div>

      {/* Findings List */}
      <div>
        <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide mb-3 flex items-center gap-2">
          <Shield size={14} /> Findings
        </h2>

        {isLoading ? (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-24 bg-gray-100 animate-pulse rounded-xl" />
            ))}
          </div>
        ) : filteredResults.length === 0 ? (
          <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-10 text-center">
            {results?.length === 0 ? (
              <>
                <CheckCircle className="w-10 h-10 text-green-400 mx-auto mb-2" />
                <p className="text-gray-500 font-medium">No findings recorded for this scan.</p>
                <p className="text-sm text-gray-400 mt-1">This may mean the scan is still running or no issues were detected.</p>
              </>
            ) : (
              <>
                <XCircle className="w-10 h-10 text-gray-300 mx-auto mb-2" />
                <p className="text-gray-500 font-medium">No findings match the current filters.</p>
                <button
                  onClick={() => { setSeverityFilter('all'); setStatusFilter('all') }}
                  className="mt-3 text-sm text-blue-600 hover:underline"
                >
                  Clear filters
                </button>
              </>
            )}
          </div>
        ) : (
          <div className="space-y-3">
            {filteredResults.map((result) => (
              <FindingCard
                key={result.id}
                result={result}
                onStatusChange={handleStatusChange}
              />
            ))}
          </div>
        )}
      </div>

      {/* Running indicator */}
      {scan?.status === 'running' && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 flex items-center gap-3">
          <Clock className="w-5 h-5 text-blue-500 shrink-0" />
          <div>
            <p className="text-sm font-semibold text-blue-800">Scan in progress</p>
            <p className="text-xs text-blue-600">Results will appear here as the scanner finds issues. Refresh to see updates.</p>
          </div>
        </div>
      )}
    </div>
  )
}

export default ScanDetail
