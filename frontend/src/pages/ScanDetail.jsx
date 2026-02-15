import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getScan, getScanResults } from '../api.js'
import { AlertOctagon, Download } from 'lucide-react'
import jsPDF from 'jspdf'
import autoTable from 'jspdf-autotable'

const ScanDetail = () => {
  const { id } = useParams()

  const { data: scan } = useQuery({
    queryKey: ['scan', id],
    queryFn: async () => {
      if (!id) throw new Error('Scan ID is required')
      return (await getScan(id)).data
    },
    enabled: !!id,
  })

  const { data: results } = useQuery({
    queryKey: ['scan-results', id],
    queryFn: async () => {
      if (!id) throw new Error('Scan ID is required')
      return (await getScanResults(id)).data
    },
    enabled: !!id,
  })

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return 'text-red-600 bg-red-50 border-red-200'
      case 'medium':
        return 'text-orange-600 bg-orange-50 border-orange-200'
      case 'low':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200'
      default:
        return 'text-blue-600 bg-blue-50 border-blue-200'
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
      return {
        id: item.id,
        name: item.name,
        status: found ? 'FOUND' : 'NOT FOUND',
      }
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
        if (!existing.endpoints.includes(endpointStr)) {
          existing.endpoints.push(endpointStr)
        }
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

      const urlObj = new URL(scan.target_url)
      const port = urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80')
      const affectedIPs = urlObj.hostname

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

  return (
    <div>
      <div className="mb-8 flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold mb-2">Scan Details #{id}</h1>
          <p className="text-gray-600">Target: {scan?.target_url}</p>
          <p className="text-gray-600">Status: {scan?.status}</p>
        </div>
        <button
          onClick={exportPDF}
          className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 flex items-center gap-2"
        >
          <Download size={16} /> Export PDF Report
        </button>
      </div>

      <div className="space-y-4">
        <h2 className="text-xl font-bold">Findings</h2>
        {results?.length === 0 && (
          <div className="text-gray-500">No findings recorded yet.</div>
        )}
        {results?.map((result) => (
          <div
            key={result.id}
            className={`p-4 rounded-lg border ${getSeverityColor(result.severity)}`}
          >
            <div className="flex justify-between items-start">
              <div className="flex items-start gap-3">
                <AlertOctagon className="mt-1 w-5 h-5 flex-shrink-0" />
                <div>
                  <h3 className="font-bold text-lg">
                    {result.rule_id}: {result.description}
                  </h3>
                  <p className="text-sm mt-1 font-mono">
                    {result.method} {result.endpoint}
                  </p>
                </div>
              </div>
              <span className="uppercase text-xs font-bold px-2 py-1 rounded bg-white bg-opacity-50">
                {result.severity}
              </span>
            </div>
            {result.details && (
              <div className="mt-4 bg-white bg-opacity-60 p-3 rounded text-sm font-mono whitespace-pre-wrap overflow-x-auto">
                {JSON.stringify(result.details, null, 2)}
              </div>
            )}
            <div className="mt-2 text-sm">
              <p>
                <strong>Remediation:</strong> {result.remediation}
              </p>
              <p>
                <strong>Impact:</strong> {result.impact}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default ScanDetail

