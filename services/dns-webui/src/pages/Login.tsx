import React from 'react';
import { useNavigate } from 'react-router-dom';
import { LoginPageBuilder } from '@penguin/react_libs';
import type { LoginResponse } from '@penguin/react_libs';
import { useAuth } from '../hooks/useAuth';

const Login: React.FC = () => {
  const navigate = useNavigate();
  const { setAuthenticated } = useAuth();

  const handleSuccess = (response: LoginResponse) => {
    if (response.token && response.user) {
      setAuthenticated(
        {
          id: Number(response.user.id),
          email: response.user.email,
          first_name: response.user.name?.split(' ')[0] || '',
          last_name: response.user.name?.split(' ').slice(1).join(' ') || '',
          is_admin: response.user.roles?.includes('admin') || false,
          is_active: true,
          created_on: '',
        },
        response.token,
        response.refreshToken || '',
      );
      navigate('/');
    }
  };

  return (
    <LoginPageBuilder
      api={{ loginUrl: '/api/v1/auth/login' }}
      branding={{
        appName: 'Squawk DNS',
        tagline: 'Enterprise DNS Management Console',
      }}
      onSuccess={handleSuccess}
      showSignUp={false}
      showForgotPassword={false}
    />
  );
};

export default Login;
