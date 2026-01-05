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

// =============================================================================
// DHCP Types
// =============================================================================

export interface DHCPPool {
  id: number;
  name: string;
  network: string;
  rangeStart: string;
  rangeEnd: string;
  gateway?: string;
  dnsServers: string[];
  ntpServers: string[];
  domainName?: string;
  leaseDuration: number;
  teamId?: number;
  active: boolean;
  enableDdns: boolean;
  ddnsZoneId?: number;
  activeLeases?: number;
  reservedIps?: number;
  statistics?: {
    totalIps: number;
    activeLeases: number;
    reservedIps: number;
    availableIps: number;
    utilizationPercent: number;
  };
  createdAt: string;
  updatedAt?: string;
}

export interface DHCPLease {
  id: number;
  poolId: number;
  macAddress: string;
  ipAddress: string;
  hostname?: string;
  leaseStart: string;
  leaseEnd: string;
  status: 'active' | 'expired' | 'released';
  remainingSeconds: number;
}

export interface DHCPReservation {
  id: number;
  poolId: number;
  macAddress: string;
  ipAddress: string;
  hostname?: string;
  description?: string;
  createdAt: string;
}

// =============================================================================
// Time Synchronization Types
// =============================================================================

export interface TimeServer {
  id: number;
  name: string;
  serverUrl: string;
  protocol: 'ptp' | 'ntp';
  stratum: number;
  priority: number;
  teamId?: number;
  active: boolean;
  status: 'synchronized' | 'unsynchronized' | 'unreachable' | 'unknown';
  lastSync?: string;
  lastOffsetMs?: number;
  lastDelayMs?: number;
  ptpConfig?: {
    domain?: number;
    transport?: string;
    delayMechanism?: string;
  };
  statistics?: {
    syncCount: number;
    syncFailures: number;
    avgOffsetMs: number;
    maxOffsetMs: number;
    avgDelayMs: number;
  };
  createdAt: string;
  updatedAt?: string;
}

export interface TimeSyncLog {
  id: number;
  serverId: number;
  serverName: string;
  protocol: string;
  offsetMs: number;
  delayMs: number;
  status: 'success' | 'failed' | 'timeout';
  errorMessage?: string;
  timestamp: string;
}

export interface TimeStatus {
  currentTime: string;
  synchronized: boolean;
  activeSource?: {
    id: number;
    name: string;
    protocol: string;
    stratum: number;
  };
  offsetMs?: number;
  delayMs?: number;
  lastSync?: string;
  fallbackAvailable: boolean;
}
