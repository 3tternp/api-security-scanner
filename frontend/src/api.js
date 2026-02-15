import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001/api/v1';

const api = axios.create({
  baseURL: API_URL,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    if (!config.headers) {
      config.headers = {};
    }
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && (error.response.status === 401 || error.response.status === 403)) {
      localStorage.removeItem('token');
      window.location.href = '/';
    }
    return Promise.reject(error);
  }
);

export const login = (username, password) => {
  const formData = new URLSearchParams();
  formData.append('username', username);
  formData.append('password', password);
  return api.post('/login/access-token', formData, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
};

export const getMe = () => api.get('/users/me');

export const createScan = (data) => api.post('/scans/', data);
export const getScans = () => api.get('/scans/');
export const getScan = (id) => api.get(`/scans/${id}`);
export const getScanResults = (id) => api.get(`/scans/${id}/results`);
export const deleteScan = (id) => api.delete(`/scans/${id}`);

export const getUsers = () => api.get('/users/');
export const createUser = (data) => api.post('/users/', data);

export default api;
