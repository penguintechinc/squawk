import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { SidebarMenu } from '@penguintechinc/react-libs';
import type { MenuCategory, MenuItem } from '@penguintechinc/react-libs';
import { useAuth } from '../hooks/useAuth';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuth();

  const categories: MenuCategory[] = [
    {
      header: 'Overview',
      items: [
        { name: 'Dashboard', href: '/' },
        { name: 'Query Log', href: '/queries' },
      ],
    },
    {
      header: 'DNS Management',
      collapsible: true,
      items: [
        { name: 'Domains', href: '/domains' },
        { name: 'Zones', href: '/zones' },
        { name: 'Records', href: '/records' },
      ],
    },
    {
      header: 'Access Control',
      collapsible: true,
      items: [
        { name: 'Users', href: '/users', roles: ['admin'] },
        { name: 'Groups', href: '/groups' },
        { name: 'Permissions', href: '/permissions', roles: ['admin'] },
      ],
    },
    {
      header: 'Security',
      collapsible: true,
      items: [
        { name: 'IOC Feeds', href: '/ioc' },
        { name: 'Blocked', href: '/blocked' },
        { name: 'Threats', href: '/threats' },
      ],
    },
  ];

  const footerItems: MenuItem[] = [
    { name: 'Settings', href: '/settings', roles: ['admin'] },
  ];

  const handleNavigate = (href: string) => {
    if (href === '#logout') {
      logout();
      navigate('/login');
      return;
    }
    navigate(href);
  };

  return (
    <div className="flex h-screen bg-slate-900">
      <SidebarMenu
        logo={
          <span className="text-xl font-bold text-amber-400">Squawk DNS</span>
        }
        categories={categories}
        currentPath={location.pathname}
        onNavigate={handleNavigate}
        footerItems={[
          ...footerItems,
          { name: 'Logout', href: '#logout' },
        ]}
        userRole={user?.is_admin ? 'admin' : 'viewer'}
      />
      <main className="flex-1 ml-64 overflow-auto">
        <div className="p-6">{children}</div>
      </main>
    </div>
  );
};

export default Layout;
