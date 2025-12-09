import { Card, CardContent, Typography, Box } from '@mui/material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { useEffect, useState } from 'react';
import api from '../../services/api';
import { QueryData } from '../../types';

export default function QueryChart() {
  const [data, setData] = useState<QueryData[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await api.get<QueryData[]>('/api/v1/dashboard/query-history');
        setData(response.data);
      } catch (error) {
        console.error('Failed to fetch query history:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 60000); // Refresh every minute

    return () => clearInterval(interval);
  }, []);

  return (
    <Card sx={{ height: 400 }}>
      <CardContent>
        <Typography variant="h6" sx={{ color: '#FFD700', mb: 3, fontWeight: 600 }}>
          Query Timeline (Last 24 Hours)
        </Typography>
        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 300 }}>
            <Typography sx={{ color: '#FFC700' }}>Loading chart data...</Typography>
          </Box>
        ) : (
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" stroke="#34495E" />
              <XAxis
                dataKey="timestamp"
                stroke="#FFD700"
                tick={{ fill: '#FFC700' }}
                tickFormatter={(value) => new Date(value).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
              />
              <YAxis stroke="#FFD700" tick={{ fill: '#FFC700' }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#2C3E50',
                  border: '1px solid #34495E',
                  borderRadius: 8,
                  color: '#FFD700',
                }}
                labelStyle={{ color: '#FFD700' }}
              />
              <Legend
                wrapperStyle={{ color: '#FFD700' }}
                iconType="line"
              />
              <Line
                type="monotone"
                dataKey="queries"
                stroke="#4CAF50"
                strokeWidth={2}
                dot={{ fill: '#4CAF50', r: 4 }}
                activeDot={{ r: 6 }}
                name="Total Queries"
              />
              <Line
                type="monotone"
                dataKey="cacheHits"
                stroke="#2196f3"
                strokeWidth={2}
                dot={{ fill: '#2196f3', r: 4 }}
                activeDot={{ r: 6 }}
                name="Cache Hits"
              />
              <Line
                type="monotone"
                dataKey="avgResponseTime"
                stroke="#ff9800"
                strokeWidth={2}
                dot={{ fill: '#ff9800', r: 4 }}
                activeDot={{ r: 6 }}
                name="Avg Response Time (ms)"
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
