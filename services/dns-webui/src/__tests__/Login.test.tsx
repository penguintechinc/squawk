import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import Login from '../pages/Login';

// Mock navigate function
const mockNavigate = vi.fn();

// Mock react-libs
vi.mock('@penguintechinc/react-libs', () => ({
  LoginPageBuilder: ({ branding, onSuccess, api }: any) => (
    <div data-testid="login-page">
      <div>{branding.appName}</div>
      <div>{branding.tagline}</div>
      <input type="text" placeholder="email" data-testid="email-input" />
      <input type="password" placeholder="password" data-testid="password-input" />
      <button
        onClick={() => onSuccess({
          token: 'test-token',
          refreshToken: 'refresh-token',
          user: {
            id: '1',
            email: 'test@example.com',
            name: 'Test User',
            roles: ['admin']
          }
        })}
        data-testid="login-button"
      >
        Login
      </button>
    </div>
  ),
}));

// Mock useAuth hook
const mockSetAuthenticated = vi.fn();
vi.mock('../hooks/useAuth', () => ({
  useAuth: () => ({
    isAuthenticated: false,
    checkAuth: vi.fn(),
    setAuthenticated: mockSetAuthenticated,
  }),
}));

// Mock useNavigate
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

describe('Login page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders LoginPageBuilder with correct app name', () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );
    expect(screen.getByTestId('login-page')).toBeInTheDocument();
    expect(screen.getByText('Squawk DNS')).toBeInTheDocument();
  });

  it('renders with correct branding props', () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );
    expect(screen.getByText('Enterprise DNS Management Console')).toBeInTheDocument();
  });

  it('renders login button', () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );
    const loginButton = screen.getByTestId('login-button');
    expect(loginButton).toBeInTheDocument();
  });

  it('calls setAuthenticated on successful login', async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    const loginButton = screen.getByTestId('login-button');
    await user.click(loginButton);

    await waitFor(() => {
      expect(mockSetAuthenticated).toHaveBeenCalledWith(
        expect.objectContaining({
          id: 1,
          email: 'test@example.com',
        })
      );
      // Tokens must never be passed to client-side state -- they arrive
      // only as HttpOnly Set-Cookie headers on the login response.
      expect(mockSetAuthenticated).not.toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        expect.anything()
      );
    });
  });

  it('navigates to root after successful login', async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    const loginButton = screen.getByTestId('login-button');
    await user.click(loginButton);

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/');
    });
  });

  it('parses user name correctly for admin role', async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    const loginButton = screen.getByTestId('login-button');
    await user.click(loginButton);

    await waitFor(() => {
      expect(mockSetAuthenticated).toHaveBeenCalledWith(
        expect.objectContaining({
          first_name: 'Test',
          last_name: 'User',
          is_admin: true,
        })
      );
    });
  });
});
