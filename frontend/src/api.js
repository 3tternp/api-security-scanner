import axios from 'axios';

const isLocalhostUrl = (value) => {
  try {
    const u = new URL(value);
    return u.hostname === 'localhost' || u.hostname === '127.0.0.1';
  } catch {
    return false;
  }
};

const resolveApiUrl = () => {
  const fromEnv = import.meta.env.VITE_API_URL;
  if (fromEnv) {
    if (!import.meta.env.DEV) {
      if (isLocalhostUrl(fromEnv) || /localhost|127\.0\.0\.1/i.test(fromEnv)) {
        return '/api/v1';
      }
    }
    return fromEnv;
  }

  if (import.meta.env.DEV) return 'http://localhost:8000/api/v1';
  return '/api/v1';
};

const API_URL = resolveApiUrl();

const api = axios.create({
  baseURL: API_URL,
});

api.interceptors.request.use((config) => {
  const url = config?.url || '';
  if (url.includes('/login/access-token')) {
    return config;
  }
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
    const url = error?.config?.url || '';
    if (url.includes('/login/access-token')) {
      return Promise.reject(error);
    }
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

// Update finding status
export const updateFindingStatus = (resultId, status) =>
  api.patch(`/scans/results/${resultId}/status`, { status });

// Get dashboard stats
export const getDashboardStats = () =>
  api.get('/scans/dashboard/stats');

// Download DOCX report - returns blob
export const downloadDocxReport = (scanId) =>
  api.get(`/scans/${scanId}/report/docx`, { responseType: 'blob' });

export default api;
