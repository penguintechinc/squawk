import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor: inject JWT
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor: handle 401, refresh token
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      const refreshToken = localStorage.getItem('refreshToken');
      if (refreshToken) {
        try {
          const response = await axios.post(`${api.defaults.baseURL}/api/v1/auth/refresh`, {
            refreshToken,
          });
          // Rotation: the server revokes the presented refresh token and
          // issues a new pair — store both or the next refresh will 401.
          const { accessToken, refreshToken: rotatedRefreshToken } = response.data;
          localStorage.setItem('accessToken', accessToken);
          if (rotatedRefreshToken) {
            localStorage.setItem('refreshToken', rotatedRefreshToken);
          }
          originalRequest.headers.Authorization = `Bearer ${accessToken}`;
          return api.request(originalRequest);
        } catch (refreshError) {
          // Refresh failed, redirect to login
          localStorage.clear();
          window.location.href = '/login';
          return Promise.reject(refreshError);
        }
      } else {
        localStorage.clear();
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export default api;
