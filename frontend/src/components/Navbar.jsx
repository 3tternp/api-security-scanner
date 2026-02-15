import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { LogOut, Shield, Users as UsersIcon } from 'lucide-react'
import { getMe } from '../api'

const Navbar = ({ setIsAuthenticated }) => {
  const [currentUser, setCurrentUser] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    getMe()
      .then((res) => {
        setCurrentUser(res.data)
      })
      .catch(() => {})
  }, [])

  const handleLogout = () => {
    localStorage.removeItem('token')
    setIsAuthenticated(false)
    navigate('/login')
  }

  return (
    <nav className="bg-slate-800 text-white shadow-lg">
      <div className="container mx-auto px-4 py-4 flex justify-between items-center">
        <Link to="/" className="flex items-center space-x-2 text-xl font-bold">
          <Shield className="w-6 h-6" />
          <span>API Scanner</span>
        </Link>
        <div className="flex space-x-6 items-center">
          <Link to="/" className="hover:text-blue-300">Dashboard</Link>
          <Link to="/scans" className="hover:text-blue-300">Scans</Link>
          {currentUser && currentUser.role === 'admin' && (
            <Link to="/users" className="hover:text-blue-300 flex items-center space-x-1">
              <UsersIcon className="w-4 h-4" />
              <span>Users</span>
            </Link>
          )}
          {currentUser && (
            <span className="px-2 py-1 text-xs rounded-full bg-slate-700 text-slate-100">
              {currentUser.role}
            </span>
          )}
          <button
            onClick={handleLogout}
            className="flex items-center space-x-1 hover:text-red-300"
          >
            <LogOut className="w-4 h-4" />
            <span>Logout</span>
          </button>
        </div>
      </div>
    </nav>
  )
}

export default Navbar
