import { Link, useNavigate } from 'react-router-dom'
import { LogOut, Shield } from 'lucide-react'

const Navbar = ({ setIsAuthenticated }) => {
  const navigate = useNavigate()

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

