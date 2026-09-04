import { create } from 'zustand';
import api from '../services/api';
import { User, AuthResponse } from '../types';

interface AuthStore {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  checkAuth: () => Promise<void>;
}

export const useAuth = create<AuthStore>((set) => ({
  user: null,
  isAuthenticated: false,
  isLoading: true,

  login: async (username: string, password: string) => {
    try {
      const response = await api.post<AuthResponse>('/api/v1/auth/login', {
        username,
        password
      });
      const { accessToken, refreshToken, user } = response.data;

      localStorage.setItem('accessToken', accessToken);
      localStorage.setItem('refreshToken', refreshToken);

      set({ user, isAuthenticated: true, isLoading: false });
    } catch (error) {
      set({ user: null, isAuthenticated: false, isLoading: false });
      throw error;
    }
  },

  logout: () => {
    // Best-effort server-side revocation of the refresh token; local state is
    // cleared regardless so logout never blocks on the network.
    const refreshToken = localStorage.getItem('refreshToken');
    if (refreshToken) {
      api.post('/api/v1/auth/logout', { refreshToken }).catch(() => {
        console.log('[useAuth] Logout revocation failed { ignored: true }');
      });
    }
    localStorage.clear();
    set({ user: null, isAuthenticated: false, isLoading: false });
    window.location.href = '/login';
  },

  checkAuth: async () => {
    const token = localStorage.getItem('accessToken');
    if (!token) {
      set({ user: null, isAuthenticated: false, isLoading: false });
      return;
    }

    try {
      const response = await api.get<User>('/api/v1/auth/me');
      set({ user: response.data, isAuthenticated: true, isLoading: false });
    } catch (error) {
      localStorage.clear();
      set({ user: null, isAuthenticated: false, isLoading: false });
    }
  },
}));
