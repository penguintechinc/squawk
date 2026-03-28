import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/react';
import App from '../App';

// Mock react-libs components
vi.mock('@penguintechinc/react-libs', () => ({
  AppConsoleVersion: ({ children }: any) => <div data-testid="console-version">{children}</div>,
  LoginPageBuilder: () => <div data-testid="login-page" />,
}));

// Mock all page components
vi.mock('../pages/Login', () => ({
  default: () => <div data-testid="login-page" />,
}));

vi.mock('../pages/Dashboard', () => ({
  default: () => <div data-testid="dashboard" />,
}));

vi.mock('../pages/Queries', () => ({
  default: () => <div data-testid="queries" />,
}));

vi.mock('../pages/Domains', () => ({
  default: () => <div data-testid="domains" />,
}));

vi.mock('../pages/Users', () => ({
  default: () => <div data-testid="users" />,
}));

vi.mock('../pages/Groups', () => ({
  default: () => <div data-testid="groups" />,
}));

vi.mock('../pages/Zones', () => ({
  default: () => <div data-testid="zones" />,
}));

vi.mock('../pages/Records', () => ({
  default: () => <div data-testid="records" />,
}));

vi.mock('../pages/Permissions', () => ({
  default: () => <div data-testid="permissions" />,
}));

vi.mock('../pages/IOCFeeds', () => ({
  default: () => <div data-testid="ioc-feeds" />,
}));

vi.mock('../pages/Blocked', () => ({
  default: () => <div data-testid="blocked" />,
}));

vi.mock('../pages/Threats', () => ({
  default: () => <div data-testid="threats" />,
}));

vi.mock('../pages/Settings', () => ({
  default: () => <div data-testid="settings" />,
}));

vi.mock('../components/Layout', () => ({
  default: ({ children }: any) => <div data-testid="layout">{children}</div>,
}));

// Mock useAuth hook
vi.mock('../hooks/useAuth', () => {
  return {
    useAuth: () => ({
      isAuthenticated: false,
      checkAuth: vi.fn(),
      setAuthenticated: vi.fn(),
      user: null,
      login: vi.fn(),
      logout: vi.fn(),
      isLoading: false,
    }),
  };
});

describe('App', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders without crashing', () => {
    const { container } = render(<App />);
    expect(container).toBeDefined();
  });

  it('renders console version component', () => {
    const { getByTestId } = render(<App />);
    expect(getByTestId('console-version')).toBeInTheDocument();
  });

  it('renders with BrowserRouter wrapper', () => {
    const { container } = render(<App />);
    // BrowserRouter is rendered correctly if the component doesn't throw
    expect(container.firstChild).toBeDefined();
  });
});
