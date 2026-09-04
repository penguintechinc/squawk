import { useNavigate, useLocation } from 'react-router-dom';
import { SidebarMenu } from '@penguintechinc/react-libs';
import type { MenuCategory } from '@penguintechinc/react-libs';
import { usePermissions } from '../../hooks/usePermissions';

export default function Sidebar() {
  const navigate = useNavigate();
  const location = useLocation();
  const permissions = usePermissions();

  const categories: MenuCategory[] = [
    {
      header: 'Overview',
      items: [{ name: 'Dashboard', href: '/' }],
    },
    {
      header: 'Infrastructure',
      collapsible: true,
      items: [
        ...(permissions.canManageServers() ? [{ name: 'DNS Servers', href: '/servers' }] : []),
        ...(permissions.canManageZones() ? [{ name: 'DNS Zones', href: '/zones' }] : []),
      ],
    },
    {
      header: 'Access',
      collapsible: true,
      items: [
        ...(permissions.canManageUsers() ? [{ name: 'Users', href: '/users' }] : []),
        ...(permissions.canManageTeams() ? [{ name: 'Teams', href: '/teams' }] : []),
      ],
    },
    {
      header: 'Reporting',
      collapsible: true,
      items: [
        ...(permissions.canViewAnalytics() ? [{ name: 'Analytics', href: '/analytics' }] : []),
      ],
    },
  ];

  return (
    <SidebarMenu
      logo={<span style={{ color: '#FFD700', fontWeight: 700, fontSize: '1.1rem' }}>Squawk Manager</span>}
      categories={categories}
      currentPath={location.pathname}
      onNavigate={(href: string) => navigate(href)}
      footerItems={[{ name: 'Settings', href: '/settings' }]}
      width="260px"
    />
  );
}
