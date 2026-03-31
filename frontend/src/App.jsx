import { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SpeedInsights } from '@vercel/speed-insights/react'
import Login from './pages/Login.jsx'
import Setup from './pages/Setup.jsx'
import Dashboard from './pages/Dashboard.jsx'
import ScanList from './pages/ScanList.jsx'
import ScanDetail from './pages/ScanDetail.jsx'
import Users from './pages/Users.jsx'
import Sidebar from './components/Sidebar.jsx'
import api from './api'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
})

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('token'))
  // null = unknown, true = setup needed, false = setup done
  const [setupRequired, setSetupRequired] = useState(null)

  useEffect(() => {
    api.get('/setup/status')
      .then((res) => setSetupRequired(res.data.setup_required))
      .catch(() => setSetupRequired(false)) // assume done if endpoint unreachable
  }, [])

  // Still checking — show spinner to avoid flash
  if (setupRequired === null) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        {setupRequired ? (
          <Routes>
            <Route path="/setup" element={<Setup onSetupComplete={() => setSetupRequired(false)} />} />
            <Route path="*" element={<Navigate to="/setup" />} />
          </Routes>
        ) : isAuthenticated ? (
          <div className="flex h-screen overflow-hidden bg-slate-50">
            <Sidebar setIsAuthenticated={setIsAuthenticated} />
            <main className="flex-1 overflow-y-auto">
              <div className="p-6 lg:p-8 max-w-screen-2xl">
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/scans" element={<ScanList />} />
                  <Route path="/scans/:id" element={<ScanDetail />} />
                  <Route path="/users" element={<Users />} />
                  <Route path="/login" element={<Navigate to="/" />} />
                  <Route path="*" element={<Navigate to="/" />} />
                </Routes>
              </div>
            </main>
          </div>
        ) : (
          <Routes>
            <Route path="/login" element={<Login setIsAuthenticated={setIsAuthenticated} />} />
            <Route path="*" element={<Navigate to="/login" />} />
          </Routes>
        )}
      </Router>
      <SpeedInsights />
    </QueryClientProvider>
  )
}

export default App
