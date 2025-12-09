import { useAuth } from './useAuth';

export function usePermissions() {
  const user = useAuth((state) => state.user);

  const hasGlobalRole = (role: string): boolean => {
    if (!user) return false;
    return user.globalRole === role || user.globalRole === 'SystemAdmin';
  };

  const canManageUsers = (): boolean => {
    if (!user) return false;
    return hasGlobalRole('SystemAdmin') || hasGlobalRole('UserManager');
  };

  const canManageTeams = (): boolean => {
    if (!user) return false;
    return hasGlobalRole('SystemAdmin') || hasGlobalRole('OrgAdmin');
  };

  const canManageServers = (): boolean => {
    if (!user) return false;
    return hasGlobalRole('SystemAdmin');
  };

  const canManageZones = (): boolean => {
    if (!user) return false;
    // Users can manage zones in their teams
    return true;
  };

  const canViewAnalytics = (): boolean => {
    if (!user) return false;
    return hasGlobalRole('SystemAdmin') || hasGlobalRole('OrgAdmin');
  };

  return {
    hasGlobalRole,
    canManageUsers,
    canManageTeams,
    canManageServers,
    canManageZones,
    canViewAnalytics,
  };
}
