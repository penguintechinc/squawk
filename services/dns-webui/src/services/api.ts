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

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  headers: { 'Content-Type': 'application/json' },
});

// Request interceptor: add Bearer token
api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = localStorage.getItem('access_token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor: handle 401 with token refresh
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (token: string) => void;
  reject: (error: unknown) => void;
}> = [];

const processQueue = (error: unknown, token: string | null = null) => {
  failedQueue.forEach((p) => (error ? p.reject(error) : p.resolve(token!)));
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const original = error.config as InternalAxiosRequestConfig & {
      _retry?: boolean;
    };

    if (error.response?.status === 401 && !original._retry) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then((token) => {
          if (original.headers)
            original.headers.Authorization = `Bearer ${token}`;
          return api(original);
        });
      }

      original._retry = true;
      isRefreshing = true;

      const refreshToken = localStorage.getItem('refresh_token');
      if (!refreshToken) {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        window.location.href = '/login';
        return Promise.reject(error);
      }

      try {
        // Flask-JWT-Extended expects refresh token in Authorization header
        const { data } = await axios.post(
          (import.meta.env.VITE_API_URL || '') + '/api/v1/auth/refresh',
          {},
          { headers: { Authorization: `Bearer ${refreshToken}` } },
        );
        const newToken = data.access_token;
        localStorage.setItem('access_token', newToken);
        if (original.headers)
          original.headers.Authorization = `Bearer ${newToken}`;
        processQueue(null, newToken);
        return api(original);
      } catch (refreshError) {
        processQueue(refreshError, null);
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        window.location.href = '/login';
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
