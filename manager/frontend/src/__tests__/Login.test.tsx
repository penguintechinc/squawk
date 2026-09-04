import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';

// Capture the onSuccess callback to call it manually in tests
let capturedOnSuccess: ((response: any) => Promise<void>) | undefined;

vi.mock('@penguintechinc/react-libs', () => ({
  LoginPageBuilder: ({
    branding,
    onSuccess,
  }: {
    branding: { appName: string };
    onSuccess: (response: any) => Promise<void>;
  }) => {
    capturedOnSuccess = onSuccess;
    return <div data-testid="login-page">{branding.appName}</div>;
  },
  AppConsoleVersion: () => null,
}));

const mockLogin = vi.fn();
vi.mock('../hooks/useAuth', () => ({
  useAuth: vi.fn((selector) => {
    const store = {
      login: mockLogin,
      user: null,
      isAuthenticated: false,
      isLoading: false,
      logout: vi.fn(),
      checkAuth: vi.fn(),
    };
    return selector ? selector(store) : store;
  }),
}));

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

describe('Login page (manager)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    capturedOnSuccess = undefined;
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

  it('calls login and navigates on successful auth with valid token and user', async () => {
    const { default: Login } = await import('../pages/Login');
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    // Simulate LoginPageBuilder calling onSuccess with a valid response
    await act(async () => {
      await capturedOnSuccess?.({
        token: 'test-token-123',
        user: { email: 'test@example.com', id: 'user-123' },
      });
    });

    expect(mockLogin).toHaveBeenCalledWith('test@example.com', '');
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('calls login with user ID when email is not provided', async () => {
    const { default: Login } = await import('../pages/Login');
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    await act(async () => {
      await capturedOnSuccess?.({
        token: 'test-token-456',
        user: { id: 'user-456', email: null },
      });
    });

    expect(mockLogin).toHaveBeenCalledWith('user-456', '');
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('does not navigate if response has no token', async () => {
    const { default: Login } = await import('../pages/Login');
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    await act(async () => {
      await capturedOnSuccess?.({
        token: null,
        user: { email: 'test@example.com', id: 'user-123' },
      });
    });

    expect(mockLogin).not.toHaveBeenCalled();
    expect(mockNavigate).not.toHaveBeenCalledWith('/');
  });

  it('does not navigate if response has no user', async () => {
    const { default: Login } = await import('../pages/Login');
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    await act(async () => {
      await capturedOnSuccess?.({
        token: 'test-token-789',
        user: null,
      });
    });

    expect(mockLogin).not.toHaveBeenCalled();
    expect(mockNavigate).not.toHaveBeenCalledWith('/');
  });

  it('handles email fallback to id when email is null', async () => {
    const { default: Login } = await import('../pages/Login');
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    // Test: email is null, should fallback to id (nullish coalescing)
    await act(async () => {
      await capturedOnSuccess?.({
        token: 'test-token-null-email',
        user: { email: null, id: 'fallback-id' },
      });
    });

    expect(mockLogin).toHaveBeenCalledWith('fallback-id', '');
  });

  it('handles email fallback to id when email is undefined', async () => {
    const { default: Login } = await import('../pages/Login');
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    // Test: email is undefined, should fallback to id
    await act(async () => {
      await capturedOnSuccess?.({
        token: 'test-token-undefined-email',
        user: { id: 'fallback-id-2' },
      });
    });

    expect(mockLogin).toHaveBeenCalledWith('fallback-id-2', '');
  });

  it('uses empty string when both email and id are missing', async () => {
    const { default: Login } = await import('../pages/Login');
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    // Test: both email and id are missing, should use empty string
    await act(async () => {
      await capturedOnSuccess?.({
        token: 'test-token-no-fallback',
        user: {},
      });
    });

    expect(mockLogin).toHaveBeenCalledWith('', '');
  });
});
