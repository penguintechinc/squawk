import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';

vi.mock('@penguintechinc/react-libs', () => ({
  LoginPageBuilder: ({ branding }: { branding: { appName: string } }) => (
    <div data-testid="login-page">{branding.appName}</div>
  ),
  AppConsoleVersion: () => null,
}));

vi.mock('../hooks/useAuth', () => ({
  useAuth: vi.fn((selector) => {
    const store = {
      login: vi.fn(),
      user: null,
      isAuthenticated: false,
      isLoading: false,
      logout: vi.fn(),
      checkAuth: vi.fn(),
    };
    return selector ? selector(store) : store;
  }),
}));

describe('Login page (manager)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders LoginPageBuilder with correct branding', async () => {
    const { default: Login } = await import('../pages/Login');
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );
    expect(screen.getByTestId('login-page')).toBeInTheDocument();
    expect(screen.getByText('Squawk DNS Manager')).toBeInTheDocument();
  });
});
