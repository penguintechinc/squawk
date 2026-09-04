// Zustand Auth Store for Squawk DNS WebUI
//
// Access/refresh JWTs are never held here or in any other JS-readable
// storage (previously localStorage, vulnerable to token exfiltration via
// XSS/compromised dependencies -- CWE-522). The server sets them as
// HttpOnly cookies (manager/backend app/services/cookie_auth.py); this
// store only tracks UI-facing auth state (current user, isAuthenticated),
// derived from the server via /auth/me, never from a token payload decoded
// client-side.

import { create } from 'zustand';
import { auth as authApi } from '../services/api';
import type { User } from '../types/api';

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  setAuthenticated: (user: User) => void;
  logout: () => void;
  checkAuth: () => Promise<void>;
}

export const useAuth = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: false,
  isLoading: true,

  login: async (email: string, password: string) => {
    try {
      const response = await authApi.login(email, password);

      if (response.success) {
        // Tokens arrive as HttpOnly Set-Cookie headers on this response --
        // there is nothing for this client to store.
        set({
          user: response.user as User,
          isAuthenticated: true,
          isLoading: false,
        });
      } else {
        throw new Error(response.error || 'Login failed');
      }
    } catch (error) {
      set({ user: null, isAuthenticated: false, isLoading: false });
      throw error;
    }
  },

  setAuthenticated: (user: User) => {
    // Tokens were already set as HttpOnly cookies by the login response
    // (see pages/Login.tsx); this only updates client-side UI state.
    set({ user, isAuthenticated: true, isLoading: false });
  },

  logout: () => {
    authApi.logout().catch(() => {
      // Ignore logout API errors, clear local state anyway
    });

    set({
      user: null,
      isAuthenticated: false,
      isLoading: false,
    });
  },

  checkAuth: async () => {
    // No client-readable token to inspect (HttpOnly cookie) -- ask the
    // server whether the current session is valid instead of decoding
    // anything locally.
    try {
      const user = await authApi.getMe();
      set({
        user,
        isAuthenticated: true,
        isLoading: false,
      });
    } catch (error) {
      set({
        user: null,
        isAuthenticated: false,
        isLoading: false,
      });
    }
  },
}));
