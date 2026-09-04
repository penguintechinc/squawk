import axios from 'axios';
import type { AxiosError, InternalAxiosRequestConfig } from 'axios';
import type {
  DashboardStats,
  Domain,
  User,
  Group,
  Zone,
  DnsRecord,
  Permission,
  QueryLog,
  IOCFeed,
  IOCEntry,
  BlockedQuery,
} from '../types/api';

// Double-submit CSRF cookie/header pair. This is NOT the auth token: it is
// a JS-readable random value the server also stores in the (non-HttpOnly)
// csrf_token cookie, and must be echoed back in a header on state-changing
// requests. It defends the cookie-auth flow against CSRF; it grants no
// access on its own. See manager/backend/app/services/cookie_auth.py.
const CSRF_COOKIE_NAME = 'csrf_token';
const CSRF_HEADER_NAME = 'X-CSRF-Token';
const MUTATING_METHODS = new Set(['post', 'put', 'patch', 'delete']);

function readCookie(name: string): string | null {
  const escaped = name.replace(/([.$?*|{}()[\]\\/+^])/g, '\\$1');
  const match = document.cookie.match(new RegExp(`(?:^|; )${escaped}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  headers: { 'Content-Type': 'application/json' },
  // The access/refresh JWTs live in HttpOnly cookies set by the server --
  // never in localStorage or any other JS-readable storage (CWE-522).
  // withCredentials sends those cookies automatically and lets the
  // browser store the Set-Cookie response from login/refresh; the token
  // value itself is never read or attached by this client.
  withCredentials: true,
});

// Request interceptor: attach the double-submit CSRF header on
// state-changing requests. GETs are side-effect-free and skip it.
api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const method = (config.method || 'get').toLowerCase();
  if (MUTATING_METHODS.has(method)) {
    const csrfToken = readCookie(CSRF_COOKIE_NAME);
    if (csrfToken && config.headers) {
      config.headers[CSRF_HEADER_NAME] = csrfToken;
    }
  }
  return config;
});

// Response interceptor: handle 401 by refreshing via the HttpOnly
// refresh_token cookie -- the browser attaches it automatically, so there
// is no token for this client to read, store, or forward manually.
let isRefreshing = false;
let failedQueue: Array<{
  resolve: () => void;
  reject: (error: unknown) => void;
}> = [];

const processQueue = (error: unknown) => {
  failedQueue.forEach((p) => (error ? p.reject(error) : p.resolve()));
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const original = error.config as InternalAxiosRequestConfig & {
      _retry?: boolean;
    };

    const isRefreshCall = original.url?.includes('/auth/refresh');
    const isAuthCheckCall = original.url?.includes('/auth/me');

    if (error.response?.status === 401 && !original._retry && !isRefreshCall) {
      if (isRefreshing) {
        return new Promise<void>((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(() => api(original));
      }

      original._retry = true;
      isRefreshing = true;

      try {
        // refresh_token cookie is sent automatically (scoped to
        // /api/v1/auth); the request interceptor above attaches the CSRF
        // header since this is a POST.
        await api.post('/api/v1/auth/refresh', {});
        processQueue(null);
        return api(original);
      } catch (refreshError) {
        processQueue(refreshError);
        // Don't hard-navigate for the silent "am I logged in" probe
        // (useAuth.checkAuth -> /auth/me) -- a logged-out visitor on
        // /login is expected to 401 here, and redirecting to the page
        // it's already on would reload-loop. Its caller already handles
        // the rejection by setting isAuthenticated=false.
        if (!isAuthCheckCall) {
          window.location.href = '/login';
        }
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }
    return Promise.reject(error);
  },
);

// --- Auth ---
export const auth = {
  login: async (email: string, password: string) => {
    const { data } = await api.post('/api/v1/auth/login', { email, password });
    return data;
  },
  logout: async () => {
    await api.post('/api/v1/auth/logout');
  },
  register: async (userData: {
    email: string;
    password: string;
    first_name: string;
    last_name: string;
  }) => {
    const { data } = await api.post('/api/v1/auth/register', userData);
    return data;
  },
  getMe: async (): Promise<User> => {
    const { data } = await api.get('/api/v1/auth/me');
    return data.user;
  },
};

// --- Dashboard ---
export const dashboard = {
  getStats: async (): Promise<DashboardStats> => {
    const { data } = await api.get('/api/v1/dashboard/stats');
    return data;
  },
};

// --- Domains ---
export const domains = {
  getDomains: async (filter?: string): Promise<Domain[]> => {
    const { data } = await api.get('/api/v1/domains', {
      params: filter ? { filter } : {},
    });
    return data.domains;
  },
  createDomain: async (domainData: Record<string, unknown>) => {
    const { data } = await api.post('/api/v1/domains', domainData);
    return data;
  },
};

// --- Users ---
export const users = {
  getUsers: async (): Promise<User[]> => {
    const { data } = await api.get('/api/v1/users');
    return data.users;
  },
  createUser: async (userData: Record<string, unknown>) => {
    const { data } = await api.post('/api/v1/users', userData);
    return data;
  },
};

// --- Groups ---
export const groups = {
  getGroups: async (): Promise<Group[]> => {
    const { data } = await api.get('/api/v1/groups');
    return data.groups;
  },
  createGroup: async (groupData: Record<string, unknown>) => {
    const { data } = await api.post('/api/v1/groups', groupData);
    return data;
  },
  searchGroups: async (q: string): Promise<string[]> => {
    const { data } = await api.get('/api/v1/search/groups', { params: { q } });
    return data.groups;
  },
};

// --- Zones ---
export const zones = {
  getZones: async (): Promise<Zone[]> => {
    const { data } = await api.get('/api/v1/zones');
    return data.zones;
  },
  createZone: async (zoneData: Record<string, unknown>) => {
    const { data } = await api.post('/api/v1/zones', zoneData);
    return data;
  },
};

// --- Records ---
export const records = {
  getRecords: async (): Promise<{ records: DnsRecord[]; zones: Zone[] }> => {
    const { data } = await api.get('/api/v1/records');
    return data;
  },
  createRecord: async (recordData: Record<string, unknown>) => {
    const { data } = await api.post('/api/v1/records', recordData);
    return data;
  },
};

// --- Permissions ---
export const permissions = {
  getPermissions: async (): Promise<{
    permissions: Permission[];
    groups: Group[];
  }> => {
    const { data } = await api.get('/api/v1/permissions');
    return data;
  },
  createPermission: async (permData: Record<string, unknown>) => {
    const { data } = await api.post('/api/v1/permissions', permData);
    return data;
  },
};

// --- Blocked ---
export const blocked = {
  getBlocked: async (): Promise<BlockedQuery[]> => {
    const { data } = await api.get('/api/v1/blocked');
    return data.blocked_queries;
  },
  clearBlocked: async () => {
    const { data } = await api.post('/api/v1/blocked/clear');
    return data;
  },
};

// --- Threats ---
export const threats = {
  getThreats: async (): Promise<{
    feeds: IOCFeed[];
    recent_entries: IOCEntry[];
  }> => {
    const { data } = await api.get('/api/v1/threats');
    return data;
  },
  updateFeeds: async () => {
    const { data } = await api.post('/api/v1/feeds/update');
    return data;
  },
};

// --- Logs ---
export const logs = {
  getLogs: async (page = 1, perPage = 100) => {
    const { data } = await api.get('/api/v1/logs', {
      params: { page, per_page: perPage },
    });
    return data;
  },
  clearLogs: async () => {
    const { data } = await api.post('/api/v1/logs/clear');
    return data;
  },
};

// --- Queries ---
export const queries = {
  getQueries: async (
    limit = 100,
    offset = 0,
  ): Promise<{ queries: QueryLog[]; total: number }> => {
    const { data } = await api.get('/api/v1/queries', {
      params: { limit, offset },
    });
    return data;
  },
};

// --- IOC Feeds ---
export const ioc = {
  getFeeds: async (): Promise<IOCFeed[]> => {
    const { data } = await api.get('/api/v1/ioc/feeds');
    return data.feeds;
  },
  createFeed: async (feedData: Record<string, unknown>) => {
    const { data } = await api.post('/api/v1/ioc/feeds', feedData);
    return data;
  },
  updateFeed: async (id: number, feedData: Record<string, unknown>) => {
    const { data } = await api.put(`/api/v1/ioc/feeds/${id}`, feedData);
    return data;
  },
  deleteFeed: async (id: number) => {
    await api.delete(`/api/v1/ioc/feeds/${id}`);
  },
};

export default api;
