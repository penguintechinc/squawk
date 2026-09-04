import { useNavigate } from 'react-router-dom';
import { LoginPageBuilder } from '@penguintechinc/react-libs';
import type { LoginResponse } from '@penguintechinc/react-libs';
import { useAuth } from '../hooks/useAuth';

export default function Login() {
  const navigate = useNavigate();
  const login = useAuth((state) => state.login);

  const handleSuccess = async (response: LoginResponse) => {
    if (response.token && response.user) {
      await login(response.user.email ?? response.user.id ?? '', '');
      navigate('/');
    }
  };

  return (
    <LoginPageBuilder
      api={{ loginUrl: '/api/v1/auth/login' }}
      branding={{
        appName: 'Squawk DNS Manager',
        tagline: 'Control Plane for DNS Server Fleet',
      }}
      onSuccess={handleSuccess}
      showSignUp={false}
      showForgotPassword={false}
    />
  );
}
