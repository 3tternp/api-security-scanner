import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getUsers, createUser } from '../api'
import { useState } from 'react'

const Users = () => {
  const queryClient = useQueryClient()
  const [form, setForm] = useState({ email: '', password: '', role: 'auditor' })
  const [error, setError] = useState('')

  const { data: users, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: async () => {
      const response = await getUsers()
      return response.data
    },
  })

  const mutation = useMutation({
    mutationFn: async (payload) => {
      const response = await createUser(payload)
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setForm({ email: '', password: '', role: 'auditor' })
      setError('')
    },
    onError: (err) => {
      const message =
        err?.response?.data?.detail || err?.message || 'Failed to create user'
      setError(message)
    },
  })

  const handleChange = (e) => {
    const { name, value } = e.target
    setForm((prev) => ({ ...prev, [name]: value }))
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    mutation.mutate({
      email: form.email,
      password: form.password,
      role: form.role,
    })
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-800">User Management</h1>

      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold mb-4">Create User</h2>
        {error && <p className="text-red-600 mb-3">{error}</p>}
        <form onSubmit={handleSubmit} className="space-y-4 max-w-md">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">
              Email
            </label>
            <input
              type="email"
              name="email"
              value={form.email}
              onChange={handleChange}
              className="w-full border border-slate-300 rounded px-3 py-2"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">
              Password
            </label>
            <input
              type="password"
              name="password"
              value={form.password}
              onChange={handleChange}
              className="w-full border border-slate-300 rounded px-3 py-2"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">
              Role
            </label>
            <select
              name="role"
              value={form.role}
              onChange={handleChange}
              className="w-full border border-slate-300 rounded px-3 py-2"
            >
              <option value="admin">admin</option>
              <option value="auditor">auditor</option>
            </select>
          </div>
          <button
            type="submit"
            disabled={mutation.isLoading}
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-60"
          >
            {mutation.isLoading ? 'Creating...' : 'Create User'}
          </button>
        </form>
      </div>

      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold mb-4">Existing Users</h2>
        {isLoading ? (
          <p>Loading users...</p>
        ) : !users || users.length === 0 ? (
          <p className="text-slate-600">No users found.</p>
        ) : (
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2 px-2">ID</th>
                <th className="text-left py-2 px-2">Email</th>
                <th className="text-left py-2 px-2">Role</th>
                <th className="text-left py-2 px-2">Active</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b">
                  <td className="py-2 px-2">{u.id}</td>
                  <td className="py-2 px-2">{u.email}</td>
                  <td className="py-2 px-2">{u.role}</td>
                  <td className="py-2 px-2">{u.is_active ? 'Yes' : 'No'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

export default Users

