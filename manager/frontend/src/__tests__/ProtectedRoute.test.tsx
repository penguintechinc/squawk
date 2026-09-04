import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';

vi.mock('../hooks/useAuth', () => ({
  useAuth: vi.fn((selector) => {
    const store = {
      isAuthenticated: true,
      isLoading: false,
      user: { id: 'test-user' },
      login: vi.fn(),
      logout: vi.fn(),
      checkAuth: vi.fn(),
    };
    return selector ? selector(store) : store;
  }),
}));

describe('ProtectedRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders children when authenticated', async () => {
    const { default: ProtectedRoute } = await import('../components/Layout/ProtectedRoute');
    render(
      <MemoryRouter>
        <ProtectedRoute>
          <div data-testid="protected-content">Protected Content</div>
        </ProtectedRoute>
      </MemoryRouter>
    );
    expect(screen.getByTestId('protected-content')).toBeInTheDocument();
  });

  it('shows loading state when isLoading is true', async () => {
    const { useAuth: useAuthMock } = await import('../hooks/useAuth');
    vi.mocked(useAuthMock).mockReturnValue({
      isAuthenticated: false,
      isLoading: true,
      user: null,
      login: vi.fn(),
      logout: vi.fn(),
      checkAuth: vi.fn(),
    } as any);

    const { default: ProtectedRoute } = await import('../components/Layout/ProtectedRoute');
    render(
      <MemoryRouter>
        <ProtectedRoute>
          <div data-testid="protected-content">Protected Content</div>
        </ProtectedRoute>
      </MemoryRouter>
    );
    // CircularProgress from MUI
    const box = screen.getByRole('progressbar', { hidden: true });
    expect(box).toBeInTheDocument();
  });

  it('redirects to login when not authenticated', async () => {
    const { useAuth: useAuthMock } = await import('../hooks/useAuth');
    vi.mocked(useAuthMock).mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
      user: null,
      login: vi.fn(),
      logout: vi.fn(),
      checkAuth: vi.fn(),
    } as any);

    const { default: ProtectedRoute } = await import('../components/Layout/ProtectedRoute');
    const { container } = render(
      <MemoryRouter initialEntries={['/']}>
        <ProtectedRoute>
          <div data-testid="protected-content">Protected Content</div>
        </ProtectedRoute>
      </MemoryRouter>
    );
    // When not authenticated and not loading, should redirect
    expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument();
  });
});
