// API Response Types for Squawk DNS WebUI

export interface LoginResponse {
  success: boolean;
  user: {
    id: number;
    email: string;
    first_name: string;
    last_name: string;
    is_admin: boolean;
  };
  access_token: string;
  refresh_token: string;
  error?: string;
}

export interface DashboardStats {
  total_queries_24h: number;
  cache_hit_rate: number;
  active_ioc_feeds: number;
  total_ioc_entries: number;
  internal_domains: number;
  ioc_blocks_24h: number;
}

export interface Domain {
  id: number;
  name: string;
  ip_address: string;
  description: string;
  access_type: string;
  is_active: boolean;
  created_on: string;
  modified_on: string;
  access_groups: string[];
}

export interface User {
  id: number;
  email: string;
  first_name: string;
  last_name: string;
  is_admin: boolean;
  is_active: boolean;
  created_on: string;
}

export interface Group {
  id: number;
  name: string;
  group_type: string;
  description: string;
  created_on: string;
}

export interface Zone {
  id: number;
  name: string;
  visibility: string;
  primary_ns: string;
  admin_email: string;
  ttl: number;
  created_on: string;
}

export interface DnsRecord {
  id: number;
  zone: string;
  name: string;
  record_type: string;
  value: string;
  ttl: number;
  created_on: string;
}

export interface Permission {
  id: number;
  group_name: string;
  zone_pattern: string;
  access_level: string;
  can_query: boolean;
  can_modify: boolean;
  created_on: string;
}

export interface QueryLog {
  id: number;
  timestamp: string;
  client_ip: string;
  domain: string;
  record_type: string;
  response_status: string;
  cache_hit: boolean;
  processing_time_ms: number;
}

export interface IOCFeed {
  id: number;
  name: string;
  url: string;
  feed_type: string;
  is_active: boolean;
  last_updated: string;
  update_frequency_hours: number;
  entry_count?: number;
}

export interface IOCEntry {
  id: number;
  feed_id: number;
  indicator: string;
  indicator_type: string;
  threat_level: string;
  description: string;
  first_seen: string;
  last_seen: string;
}

export interface BlockedQuery {
  id: number;
  domain: string;
  client_ip: string;
  reason: string;
  threat_level: string;
  feed_source: string;
  blocked_at: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
}

export interface ApiError {
  error: string;
  message: string;
}
