import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Dashboard from './pages/Dashboard.jsx'
import ScanList from './pages/ScanList.jsx'
import ScanDetail from './pages/ScanDetail.jsx'
import Sidebar from './components/Sidebar.jsx'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
})

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <div className="flex h-screen overflow-hidden bg-slate-50">
          <Sidebar />
          <main className="flex-1 overflow-y-auto">
            <div className="p-6 lg:p-8 max-w-screen-2xl">
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/scans" element={<ScanList />} />
                <Route path="/scans/:id" element={<ScanDetail />} />
                <Route path="*" element={<Navigate to="/" />} />
              </Routes>
            </div>
          </main>
        </div>
      </Router>
    </QueryClientProvider>
  )
}

export default App
