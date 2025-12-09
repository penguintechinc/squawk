import { Card, CardContent, Typography, Grid, Box } from '@mui/material';
import { TrendingUp, Speed, Dns, People } from '@mui/icons-material';
import { useEffect, useState } from 'react';
import api from '../../services/api';
import { DashboardStats } from '../../types';

export default function StatsOverview() {
  const [stats, setStats] = useState<DashboardStats>({
    totalQueries: 0,
    cacheHitRate: 0,
    activeServers: 0,
    activeUsers: 0,
    queriesLastHour: 0,
    avgResponseTime: 0,
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await api.get<DashboardStats>('/api/v1/dashboard/stats');
        setStats(response.data);
      } catch (error) {
        console.error('Failed to fetch dashboard stats:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, []);

  const statCards = [
    {
      title: 'Total Queries',
      value: stats.totalQueries.toLocaleString(),
      subtitle: `${stats.queriesLastHour.toLocaleString()} last hour`,
      icon: <TrendingUp fontSize="large" />,
      color: '#4CAF50',
    },
    {
      title: 'Cache Hit Rate',
      value: `${stats.cacheHitRate.toFixed(1)}%`,
      subtitle: 'Cache performance',
      icon: <Speed fontSize="large" />,
      color: '#2196f3',
    },
    {
      title: 'Active Servers',
      value: stats.activeServers.toString(),
      subtitle: 'DNS servers online',
      icon: <Dns fontSize="large" />,
      color: '#ff9800',
    },
    {
      title: 'Active Users',
      value: stats.activeUsers.toString(),
      subtitle: 'Registered users',
      icon: <People fontSize="large" />,
      color: '#9c27b0',
    },
  ];

  if (loading) {
    return (
      <Grid container spacing={3}>
        {[1, 2, 3, 4].map((i) => (
          <Grid item xs={12} sm={6} md={3} key={i}>
            <Card sx={{ height: 160 }}>
              <CardContent>
                <Typography variant="h6" sx={{ color: '#FFC700' }}>
                  Loading...
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    );
  }

  return (
    <Grid container spacing={3}>
      {statCards.map((card) => (
        <Grid item xs={12} sm={6} md={3} key={card.title}>
          <Card
            sx={{
              height: 160,
              position: 'relative',
              overflow: 'visible',
              '&:hover': {
                transform: 'translateY(-4px)',
                transition: 'transform 0.2s',
                boxShadow: `0 4px 20px ${card.color}40`,
              },
            }}
          >
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="subtitle2" sx={{ color: '#FFC700', opacity: 0.8 }}>
                  {card.title}
                </Typography>
                <Box sx={{ color: card.color }}>{card.icon}</Box>
              </Box>
              <Typography variant="h3" sx={{ color: '#FFD700', fontWeight: 700, mb: 1 }}>
                {card.value}
              </Typography>
              <Typography variant="caption" sx={{ color: '#FFC700', opacity: 0.7 }}>
                {card.subtitle}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      ))}
    </Grid>
  );
}
