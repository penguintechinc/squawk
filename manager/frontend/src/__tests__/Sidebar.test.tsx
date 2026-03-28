import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';

vi.mock('@penguintechinc/react-libs', () => ({
  SidebarMenu: ({
    logo,
    categories,
  }: {
    logo: React.ReactNode;
    categories: Array<{ header: string }>;
  }) => (
    <nav data-testid="sidebar-menu">
      <div data-testid="sidebar-logo">{logo}</div>
      {categories.map((c) => (
        <div key={c.header} data-testid={`category-${c.header}`}>
          {c.header}
        </div>
      ))}
    </nav>
  ),
  AppConsoleVersion: () => null,
}));

vi.mock('../hooks/usePermissions', () => ({
  usePermissions: () => ({
    hasGlobalRole: () => true,
    canManageServers: () => true,
    canManageUsers: () => true,
    canManageTeams: () => true,
    canManageZones: () => true,
    canViewAnalytics: () => true,
  }),
}));

describe('Sidebar (manager)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
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
});
