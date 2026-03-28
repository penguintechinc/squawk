import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';

// Track categories passed to SidebarMenu to verify permission-based filtering
let capturedCategories: any[] = [];
let capturedOnNavigate: ((href: string) => void) | undefined;

vi.mock('@penguintechinc/react-libs', () => ({
  SidebarMenu: ({
    logo,
    categories,
    onNavigate,
  }: {
    logo: React.ReactNode;
    categories: Array<{ header: string; items: any[] }>;
    onNavigate: (href: string) => void;
  }) => {
    capturedCategories = categories;
    capturedOnNavigate = onNavigate;
    return (
      <nav data-testid="sidebar-menu">
        <div data-testid="sidebar-logo">{logo}</div>
        {categories.map((c) => (
          <div key={c.header} data-testid={`category-${c.header}`}>
            {c.header}
            {c.items.map((item: any) => (
              <button
                key={item.name}
                data-testid={`menu-item-${item.name}`}
                onClick={() => onNavigate(item.href)}
              >
                {item.name}
              </button>
            ))}
          </div>
        ))}
      </nav>
    );
  },
  AppConsoleVersion: () => null,
}));

const mockUsePermissions = vi.fn();
vi.mock('../hooks/usePermissions', () => ({
  usePermissions: () => mockUsePermissions(),
}));

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

describe('Sidebar (manager)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    capturedCategories = [];
    capturedOnNavigate = undefined;
    // Default: all permissions granted
    mockUsePermissions.mockReturnValue({
      hasGlobalRole: () => true,
      canManageServers: () => true,
      canManageUsers: () => true,
      canManageTeams: () => true,
      canManageZones: () => true,
      canViewAnalytics: () => true,
    });
  });

  it('renders SidebarMenu with correct categories', async () => {
    const { default: Sidebar } = await import('../components/Layout/Sidebar');
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    );
    expect(screen.getByTestId('sidebar-menu')).toBeInTheDocument();
    expect(screen.getByTestId('category-Overview')).toBeInTheDocument();
    expect(screen.getByTestId('category-Access')).toBeInTheDocument();
  });

  it('shows manager logo text', async () => {
    const { default: Sidebar } = await import('../components/Layout/Sidebar');
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    );
    const logoElement = screen.getByTestId('sidebar-logo');
    expect(logoElement.textContent).toContain('Squawk Manager');
  });

  it('includes Infrastructure category with proper header', async () => {
    const { default: Sidebar } = await import('../components/Layout/Sidebar');
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    );
    expect(screen.getByTestId('category-Infrastructure')).toBeInTheDocument();
  });

  it('includes Reporting category with proper header', async () => {
    const { default: Sidebar } = await import('../components/Layout/Sidebar');
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    );
    expect(screen.getByTestId('category-Reporting')).toBeInTheDocument();
  });

  it('shows all menu items when user has all permissions', async () => {
    const { default: Sidebar } = await import('../components/Layout/Sidebar');
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    );

    expect(screen.getByTestId('menu-item-DNS Servers')).toBeInTheDocument();
    expect(screen.getByTestId('menu-item-DNS Zones')).toBeInTheDocument();
    expect(screen.getByTestId('menu-item-Users')).toBeInTheDocument();
    expect(screen.getByTestId('menu-item-Teams')).toBeInTheDocument();
    expect(screen.getByTestId('menu-item-Analytics')).toBeInTheDocument();
  });

  it('hides DNS Servers when user cannot manage servers', async () => {
    mockUsePermissions.mockReturnValue({
      hasGlobalRole: () => true,
      canManageServers: () => false,
      canManageUsers: () => true,
      canManageTeams: () => true,
      canManageZones: () => true,
      canViewAnalytics: () => true,
    });

    const { default: Sidebar } = await import('../components/Layout/Sidebar');
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    );

    expect(screen.queryByTestId('menu-item-DNS Servers')).not.toBeInTheDocument();
    expect(screen.getByTestId('menu-item-DNS Zones')).toBeInTheDocument();
  });

  it('hides DNS Zones when user cannot manage zones', async () => {
    mockUsePermissions.mockReturnValue({
      hasGlobalRole: () => true,
      canManageServers: () => true,
      canManageUsers: () => true,
      canManageTeams: () => true,
      canManageZones: () => false,
      canViewAnalytics: () => true,
    });

    const { default: Sidebar } = await import('../components/Layout/Sidebar');
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    );

    expect(screen.getByTestId('menu-item-DNS Servers')).toBeInTheDocument();
    expect(screen.queryByTestId('menu-item-DNS Zones')).not.toBeInTheDocument();
  });

  it('hides Users when user cannot manage users', async () => {
    mockUsePermissions.mockReturnValue({
      hasGlobalRole: () => true,
      canManageServers: () => true,
      canManageUsers: () => false,
      canManageTeams: () => true,
      canManageZones: () => true,
      canViewAnalytics: () => true,
    });

    const { default: Sidebar } = await import('../components/Layout/Sidebar');
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    );

    expect(screen.queryByTestId('menu-item-Users')).not.toBeInTheDocument();
    expect(screen.getByTestId('menu-item-Teams')).toBeInTheDocument();
  });

  it('hides Teams when user cannot manage teams', async () => {
    mockUsePermissions.mockReturnValue({
      hasGlobalRole: () => true,
      canManageServers: () => true,
      canManageUsers: () => true,
      canManageTeams: () => false,
      canManageZones: () => true,
      canViewAnalytics: () => true,
    });

    const { default: Sidebar } = await import('../components/Layout/Sidebar');
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    );

    expect(screen.queryByTestId('menu-item-Teams')).not.toBeInTheDocument();
    expect(screen.getByTestId('menu-item-Users')).toBeInTheDocument();
  });

  it('hides Analytics when user cannot view analytics', async () => {
    mockUsePermissions.mockReturnValue({
      hasGlobalRole: () => true,
      canManageServers: () => true,
      canManageUsers: () => true,
      canManageTeams: () => true,
      canManageZones: () => true,
      canViewAnalytics: () => false,
    });

    const { default: Sidebar } = await import('../components/Layout/Sidebar');
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    );

    expect(screen.queryByTestId('menu-item-Analytics')).not.toBeInTheDocument();
  });

  it('calls navigate when menu item is clicked', async () => {
    const { default: Sidebar } = await import('../components/Layout/Sidebar');
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    );

    // Click on Dashboard menu item
    const dashboardButton = screen.getByTestId('menu-item-Dashboard');
    dashboardButton.click();
    expect(mockNavigate).toHaveBeenCalledWith('/');

    mockNavigate.mockClear();

    // Click on DNS Servers menu item
    const serversButton = screen.getByTestId('menu-item-DNS Servers');
    serversButton.click();
    expect(mockNavigate).toHaveBeenCalledWith('/servers');

    mockNavigate.mockClear();

    // Click on Users menu item
    const usersButton = screen.getByTestId('menu-item-Users');
    usersButton.click();
    expect(mockNavigate).toHaveBeenCalledWith('/users');
  });

  it('filters items correctly with multiple permission combinations', async () => {
    mockUsePermissions.mockReturnValue({
      hasGlobalRole: () => true,
      canManageServers: () => false,
      canManageUsers: () => false,
      canManageTeams: () => true,
      canManageZones: () => false,
      canViewAnalytics: () => true,
    });

    const { default: Sidebar } = await import('../components/Layout/Sidebar');
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    );

    // Should show Dashboard
    expect(screen.getByTestId('menu-item-Dashboard')).toBeInTheDocument();
    // Should hide Infrastructure items (all permissions false)
    expect(screen.queryByTestId('menu-item-DNS Servers')).not.toBeInTheDocument();
    expect(screen.queryByTestId('menu-item-DNS Zones')).not.toBeInTheDocument();
    // Should hide Users (canManageUsers false)
    expect(screen.queryByTestId('menu-item-Users')).not.toBeInTheDocument();
    // Should show Teams (canManageTeams true)
    expect(screen.getByTestId('menu-item-Teams')).toBeInTheDocument();
    // Should show Analytics (canViewAnalytics true)
    expect(screen.getByTestId('menu-item-Analytics')).toBeInTheDocument();
  });
});
