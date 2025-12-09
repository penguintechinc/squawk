import { create } from 'zustand';
import api from '../services/api';
import { LicenseInfo } from '../types';

interface LicenseStore {
  license: LicenseInfo | null;
  isLoading: boolean;
  fetchLicense: () => Promise<void>;
  hasFeature: (feature: string) => boolean;
  isSelfHosted: () => boolean;
  isCloudHosted: () => boolean;
  isCommunity: () => boolean;
}

export const useLicense = create<LicenseStore>((set, get) => ({
  license: null,
  isLoading: true,

  fetchLicense: async () => {
    try {
      const response = await api.get<LicenseInfo>('/api/v1/license/info');
      set({ license: response.data, isLoading: false });
    } catch (error) {
      // Default to community if license check fails
      set({
        license: {
          tier: 'community',
          features: ['basic_dns', 'basic_cache', 'mtls'],
          userCount: 0,
        },
        isLoading: false
      });
    }
  },

  hasFeature: (feature: string): boolean => {
    const { license } = get();
    return license?.features.includes(feature) || false;
  },

  isSelfHosted: (): boolean => {
    const { license } = get();
    return license?.tier === 'self-hosted';
  },

  isCloudHosted: (): boolean => {
    const { license } = get();
    return license?.tier === 'cloud-hosted';
  },

  isCommunity: (): boolean => {
    const { license } = get();
    return license?.tier === 'community' || !license;
  },
}));

// Feature flags based on license tier
export const ENTERPRISE_FEATURES = {
  SSO: 'sso_integration',
  LDAP: 'ldap_integration',
  SAML: 'saml_integration',
  SCIM: 'scim_provisioning',
  SELECTIVE_ROUTING: 'selective_dns_routing',
  ADVANCED_ANALYTICS: 'advanced_analytics',
  PRIORITY_SUPPORT: 'priority_support',
  UNLIMITED_THREAT_INTEL: 'unlimited_threat_intel',
  MULTI_TENANT: 'multi_tenant',
};

export const CLOUD_FEATURES = {
  MANAGED_INFRASTRUCTURE: 'managed_infrastructure',
  AUTO_UPDATES: 'auto_updates',
  COMPLIANCE_REPORTING: 'compliance_reporting',
  ADVANCED_MONITORING: 'advanced_monitoring',
  CUSTOM_DEVELOPMENT: 'custom_development',
  GLOBAL_CDN: 'global_cdn',
  CURATED_THREAT_INTEL: 'curated_threat_intel',
};
