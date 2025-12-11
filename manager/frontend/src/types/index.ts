export interface User {
  id: number;
  username: string;
  email: string;
  globalRole: string;
  createdAt: string;
  updatedAt: string;
}

export interface Team {
  id: number;
  name: string;
  description?: string;
  memberCount?: number;
  createdAt: string;
  updatedAt: string;
}

export interface DNSServer {
  id: number;
  name: string;
  serverUrl: string;
  status: 'online' | 'offline' | 'degraded';
  lastHeartbeat?: string;
  version?: string;
  createdAt: string;
  updatedAt: string;
}

export interface DNSZone {
  id: number;
  name: string;
  teamId: number;
  teamName?: string;
  visibility: 'PUBLIC' | 'INTERNAL' | 'RESTRICTED' | 'PRIVATE';
  recordCount?: number;
  createdAt: string;
  updatedAt: string;
}

export interface DNSRecord {
  id: number;
  zoneId: number;
  name: string;
  type: string;
  value: string;
  ttl: number;
  priority?: number;
  createdAt: string;
  updatedAt: string;
}

export interface DashboardStats {
  totalQueries: number;
  cacheHitRate: number;
  activeServers: number;
  activeUsers: number;
  queriesLastHour: number;
  avgResponseTime: number;
}

export interface QueryData {
  timestamp: string;
  queries: number;
  cacheHits: number;
  avgResponseTime: number;
}

export interface LicenseInfo {
  tier: 'community' | 'self-hosted' | 'cloud-hosted';
  expiresAt?: string;
  features: string[];
  userCount: number;
  maxUsers?: number;
}

export interface TeamMember {
  id: number;
  userId: number;
  teamId: number;
  role: string;
  username?: string;
  email?: string;
}

export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
  user: User;
}
