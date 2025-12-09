import { Card, CardContent, Typography, Grid, Box, Chip } from '@mui/material';
import { CheckCircle, Error, Warning } from '@mui/icons-material';
import { useEffect, useState } from 'react';
import api from '../../services/api';
import { DNSServer } from '../../types';

export default function DNSServerFleet() {
  const [servers, setServers] = useState<DNSServer[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchServers = async () => {
      try {
        const response = await api.get<DNSServer[]>('/api/v1/dns-servers');
        setServers(response.data);
      } catch (error) {
        console.error('Failed to fetch DNS servers:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchServers();
    const interval = setInterval(fetchServers, 10000); // Refresh every 10 seconds

    return () => clearInterval(interval);
  }, []);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'online':
        return <CheckCircle sx={{ color: '#4CAF50' }} />;
      case 'offline':
        return <Error sx={{ color: '#f44336' }} />;
      case 'degraded':
        return <Warning sx={{ color: '#ff9800' }} />;
      default:
        return <Warning sx={{ color: '#9e9e9e' }} />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
        return '#4CAF50';
      case 'offline':
        return '#f44336';
      case 'degraded':
        return '#ff9800';
      default:
        return '#9e9e9e';
    }
  };

  const getTimeSinceHeartbeat = (lastHeartbeat?: string) => {
    if (!lastHeartbeat) return 'Never';
    const seconds = Math.floor((Date.now() - new Date(lastHeartbeat).getTime()) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };

  if (loading) {
    return (
      <Card>
        <CardContent>
          <Typography variant="h6" sx={{ color: '#FFD700', mb: 2 }}>
            DNS Server Fleet
          </Typography>
          <Typography sx={{ color: '#FFC700' }}>Loading servers...</Typography>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" sx={{ color: '#FFD700', mb: 3, fontWeight: 600 }}>
          DNS Server Fleet
        </Typography>
        <Grid container spacing={2}>
          {servers.length === 0 ? (
            <Grid item xs={12}>
              <Typography sx={{ color: '#FFC700', textAlign: 'center', py: 4 }}>
                No DNS servers registered
              </Typography>
            </Grid>
          ) : (
            servers.map((server) => (
              <Grid item xs={12} sm={6} md={4} key={server.id}>
                <Card
                  sx={{
                    backgroundColor: '#34495E',
                    border: `2px solid ${getStatusColor(server.status)}`,
                    '&:hover': {
                      transform: 'translateY(-2px)',
                      transition: 'transform 0.2s',
                      boxShadow: `0 4px 12px ${getStatusColor(server.status)}40`,
                    },
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', mb: 2 }}>
                      <Box>
                        <Typography variant="h6" sx={{ color: '#FFD700', fontWeight: 600 }}>
                          {server.name}
                        </Typography>
                        <Typography variant="caption" sx={{ color: '#FFC700', opacity: 0.8 }}>
                          {server.serverUrl}
                        </Typography>
                      </Box>
                      {getStatusIcon(server.status)}
                    </Box>

                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                      <Chip
                        label={server.status.toUpperCase()}
                        size="small"
                        sx={{
                          backgroundColor: getStatusColor(server.status),
                          color: '#fff',
                          fontWeight: 600,
                          width: 'fit-content',
                        }}
                      />
                      <Typography variant="caption" sx={{ color: '#FFC700' }}>
                        Last heartbeat: {getTimeSinceHeartbeat(server.lastHeartbeat)}
                      </Typography>
                      {server.version && (
                        <Typography variant="caption" sx={{ color: '#FFC700', opacity: 0.7 }}>
                          Version: {server.version}
                        </Typography>
                      )}
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))
          )}
        </Grid>
      </CardContent>
    </Card>
  );
}
