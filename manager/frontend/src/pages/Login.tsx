import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Card,
  CardContent,
  TextField,
  Button,
  Typography,
  Alert,
  Container,
} from '@mui/material';
import { Lock } from '@mui/icons-material';
import { useAuth } from '../hooks/useAuth';

export default function Login() {
  const navigate = useNavigate();
  const login = useAuth((state) => state.login);
  const [formData, setFormData] = useState({
    username: '',
    password: '',
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await login(formData.username, formData.password);
      navigate('/');
    } catch (err: any) {
      setError(err.response?.data?.message || 'Invalid credentials');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#1a1a1a',
        backgroundImage: 'radial-gradient(circle at 50% 50%, #2C3E71 0%, #1a1a1a 100%)',
      }}
    >
      <Container maxWidth="sm">
        <Box sx={{ textAlign: 'center', mb: 4 }}>
          <Typography
            variant="h3"
            sx={{
              color: '#FFD700',
              fontWeight: 700,
              mb: 1,
              textShadow: '0 0 20px rgba(255, 215, 0, 0.3)',
            }}
          >
            Squawk DNS Manager
          </Typography>
          <Typography variant="body1" sx={{ color: '#FFC700' }}>
            Control Plane for DNS Server Fleet
          </Typography>
        </Box>

        <Card
          sx={{
            backgroundColor: '#2C3E50',
            border: '1px solid #34495E',
            boxShadow: '0 8px 32px rgba(44, 62, 113, 0.3)',
          }}
        >
          <CardContent sx={{ p: 4 }}>
            <Box sx={{ display: 'flex', justifyContent: 'center', mb: 3 }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: '50%',
                  backgroundColor: '#2C3E71',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Lock sx={{ fontSize: 40, color: '#FFD700' }} />
              </Box>
            </Box>

            <Typography
              variant="h5"
              align="center"
              sx={{ color: '#FFD700', mb: 3, fontWeight: 600 }}
            >
              Sign In
            </Typography>

            {error && (
              <Alert
                severity="error"
                sx={{
                  mb: 3,
                  backgroundColor: '#2C3E50',
                  border: '1px solid #f44336',
                  color: '#FFD700',
                }}
              >
                {error}
              </Alert>
            )}

            <form onSubmit={handleSubmit}>
              <TextField
                fullWidth
                label="Username"
                value={formData.username}
                onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                margin="normal"
                required
                autoFocus
                autoComplete="username"
              />
              <TextField
                fullWidth
                label="Password"
                type="password"
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                margin="normal"
                required
                autoComplete="current-password"
              />
              <Button
                type="submit"
                fullWidth
                variant="contained"
                size="large"
                disabled={loading}
                sx={{
                  mt: 3,
                  py: 1.5,
                  backgroundColor: '#2C3E71',
                  color: '#FFD700',
                  fontWeight: 600,
                  fontSize: '1.1rem',
                  '&:hover': {
                    backgroundColor: '#1a2642',
                    boxShadow: '0 0 20px rgba(44, 62, 113, 0.5)',
                  },
                }}
              >
                {loading ? 'Signing In...' : 'Sign In'}
              </Button>
            </form>

            <Box sx={{ mt: 3, textAlign: 'center' }}>
              <Typography variant="caption" sx={{ color: '#FFC700', opacity: 0.7 }}>
                Version 2.1.0
              </Typography>
            </Box>
          </CardContent>
        </Card>

        <Box sx={{ mt: 3, textAlign: 'center' }}>
          <Typography variant="body2" sx={{ color: '#FFC700', opacity: 0.7 }}>
            Powered by Penguin Technologies
          </Typography>
        </Box>
      </Container>
    </Box>
  );
}
