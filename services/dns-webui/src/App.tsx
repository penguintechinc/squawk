import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AppConsoleVersion as ConsoleVersionComponent } from '@penguintechinc/react-libs';
import { useAuth } from './hooks/useAuth';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Queries from './pages/Queries';
import Domains from './pages/Domains';
import Users from './pages/Users';
import Groups from './pages/Groups';
import Zones from './pages/Zones';
import Records from './pages/Records';
import Permissions from './pages/Permissions';
import IOCFeeds from './pages/IOCFeeds';
import Blocked from './pages/Blocked';
import Threats from './pages/Threats';
import Settings from './pages/Settings';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
};

const AppRoutes: React.FC = () => {
  const { checkAuth } = useAuth();

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout>
              <Dashboard />
            </Layout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/queries"
        element={
          <ProtectedRoute>
            <Layout>
              <Queries />
            </Layout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/domains"
        element={
          <ProtectedRoute>
            <Layout>
              <Domains />
            </Layout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/users"
        element={
          <ProtectedRoute>
            <Layout>
              <Users />
            </Layout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/groups"
        element={
          <ProtectedRoute>
            <Layout>
              <Groups />
            </Layout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/zones"
        element={
          <ProtectedRoute>
            <Layout>
              <Zones />
            </Layout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/records"
        element={
          <ProtectedRoute>
            <Layout>
              <Records />
            </Layout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/permissions"
        element={
          <ProtectedRoute>
            <Layout>
              <Permissions />
            </Layout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/ioc"
        element={
          <ProtectedRoute>
            <Layout>
              <IOCFeeds />
            </Layout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/blocked"
        element={
          <ProtectedRoute>
            <Layout>
              <Blocked />
            </Layout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/threats"
        element={
          <ProtectedRoute>
            <Layout>
              <Threats />
            </Layout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/settings"
        element={
          <ProtectedRoute>
            <Layout>
              <Settings />
            </Layout>
          </ProtectedRoute>
        }
      />
    </Routes>
  );
};

const App: React.FC = () => {
  return (
    <BrowserRouter>
      {React.createElement(ConsoleVersionComponent as React.FC<any>,
        { appName: 'Squawk DNS WebUI', webuiVersion: '2.1.0' },
        React.createElement(AppRoutes)
      )}
    </BrowserRouter>
  );
};

export default App;
