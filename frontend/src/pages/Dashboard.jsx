import { Link } from 'react-router-dom'
import { PlusCircle, List } from 'lucide-react'

const Dashboard = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold mb-2">Dashboard</h1>
        <p className="text-sm text-gray-600">
          Overview of your API scans and OWASP API Top 10 coverage.
        </p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Link
          to="/scans"
          className="block p-6 bg-white rounded-lg shadow-md hover:shadow-xl transition-shadow border border-gray-200"
        >
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold">Recent Scans</h2>
            <List className="text-blue-500 w-8 h-8" />
          </div>
          <p className="text-gray-600">
            View and manage your recent API security scans.
          </p>
        </Link>
        <div className="p-6 bg-white rounded-lg shadow-md border border-gray-200">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold">New Scan</h2>
            <PlusCircle className="text-green-500 w-8 h-8" />
          </div>
          <p className="text-gray-600 mb-4">
            Start a new security scan for your API.
          </p>
          <Link
            to="/scans"
            className="inline-block bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600"
          >
            Go to Scans
          </Link>
        </div>
      </div>
      <div className="bg-white rounded-lg shadow-md border border-gray-200 p-6">
        <h2 className="text-xl font-semibold mb-2">OWASP API Top 10</h2>
        <p className="text-xs text-gray-600 mb-3">
          These are the core API security risk categories this scanner focuses on, with their
          typical severity rating.
        </p>
        <ul className="space-y-1 text-xs text-gray-800">
          <li className="flex justify-between items-center">
            <span>
              <span className="font-semibold">API1</span> – Broken Object Level Authorization
            </span>
            <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-700">
              Critical
            </span>
          </li>
          <li className="flex justify-between items-center">
            <span>
              <span className="font-semibold">API2</span> – Broken Authentication
            </span>
            <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-700">
              Critical
            </span>
          </li>
          <li className="flex justify-between items-center">
            <span>
              <span className="font-semibold">API3</span> – Broken Object Property Level Authorization
            </span>
            <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-700">
              Critical
            </span>
          </li>
          <li className="flex justify-between items-center">
            <span>
              <span className="font-semibold">API4</span> – Unrestricted Resource Consumption
            </span>
            <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-orange-100 text-orange-700">
              High
            </span>
          </li>
          <li className="flex justify-between items-center">
            <span>
              <span className="font-semibold">API5</span> – Broken Function Level Authorization
            </span>
            <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-700">
              Critical
            </span>
          </li>
          <li className="flex justify-between items-center">
            <span>
              <span className="font-semibold">API6</span> – Unrestricted Access to Sensitive Business Flows
            </span>
            <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-700">
              Critical
            </span>
          </li>
          <li className="flex justify-between items-center">
            <span>
              <span className="font-semibold">API7</span> – Server Side Request Forgery
            </span>
            <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-orange-100 text-orange-700">
              High
            </span>
          </li>
          <li className="flex justify-between items-center">
            <span>
              <span className="font-semibold">API8</span> – Security Misconfiguration
            </span>
            <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-700">
              Critical
            </span>
          </li>
          <li className="flex justify-between items-center">
            <span>
              <span className="font-semibold">API9</span> – Improper Inventory Management
            </span>
            <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-orange-100 text-orange-700">
              High
            </span>
          </li>
          <li className="flex justify-between items-center">
            <span>
              <span className="font-semibold">API10</span> – Unsafe Consumption of APIs
            </span>
            <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-orange-100 text-orange-700">
              High
            </span>
          </li>
        </ul>
      </div>
    </div>
  )
}

export default Dashboard
