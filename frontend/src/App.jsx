import { useState } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Login from './pages/Login.jsx'
import Dashboard from './pages/Dashboard.jsx'
import ScanList from './pages/ScanList.jsx'
import ScanDetail from './pages/ScanDetail.jsx'
import Users from './pages/Users.jsx'
import Navbar from './components/Navbar.jsx'

const queryClient = new QueryClient()

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('token'))

  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <div className="min-h-screen bg-gray-50">
          {isAuthenticated && <Navbar setIsAuthenticated={setIsAuthenticated} />}
          <div className="container mx-auto px-4 py-8">
            <Routes>
              <Route
                path="/login"
                element={
                  !isAuthenticated ? (
                    <Login setIsAuthenticated={setIsAuthenticated} />
                  ) : (
                    <Navigate to="/" />
                  )
                }
              />
              <Route
                path="/"
                element={isAuthenticated ? <Dashboard /> : <Navigate to="/login" />}
              />
              <Route
                path="/scans"
                element={isAuthenticated ? <ScanList /> : <Navigate to="/login" />}
              />
              <Route
                path="/scans/:id"
                element={isAuthenticated ? <ScanDetail /> : <Navigate to="/login" />}
              />
              <Route
                path="/users"
                element={isAuthenticated ? <Users /> : <Navigate to="/login" />}
              />
            </Routes>
          </div>
        </div>
      </Router>
    </QueryClientProvider>
  )
}

export default App
