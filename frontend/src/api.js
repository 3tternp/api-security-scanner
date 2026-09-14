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

export const createScan = (data) => api.post('/scans/', data);
export const getScans = () => api.get('/scans/');
export const getScan = (id) => api.get(`/scans/${id}`);
export const getScanResults = (id) => api.get(`/scans/${id}/results`);
export const deleteScan = (id) => api.delete(`/scans/${id}`);

// Update finding status
export const updateFindingStatus = (resultId, status) =>
  api.patch(`/scans/results/${resultId}/status`, { status });

// Get dashboard stats
export const getDashboardStats = () =>
  api.get('/scans/dashboard/stats');

// Get backend app version
export const getVersion = () => api.get('/version');

// Download DOCX report - returns blob
export const downloadDocxReport = (scanId) =>
  api.get(`/scans/${scanId}/report/docx`, { responseType: 'blob' });

export default api;
