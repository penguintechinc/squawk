import { Box, Toolbar, Typography, Grid, Card, CardContent } from '@mui/material';
import Navbar from '../components/Layout/Navbar';
import Sidebar from '../components/Layout/Sidebar';
import QueryChart from '../components/Dashboard/QueryChart';

export default function Analytics() {
  return (
    <Box sx={{ display: 'flex', backgroundColor: '#1a1a1a', minHeight: '100vh' }}>
      <Navbar />
      <Sidebar />
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { sm: `calc(100% - 260px)` },
          ml: { sm: '260px' },
        }}
      >
        <Toolbar />
        <Box sx={{ mt: 3 }}>
          <Typography variant="h4" sx={{ color: '#FFD700', mb: 3, fontWeight: 600 }}>
            Analytics
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12}>
              <QueryChart />
            </Grid>

            <Grid item xs={12} md={6}>
              <Card sx={{ height: 400 }}>
                <CardContent>
                  <Typography variant="h6" sx={{ color: '#FFD700', mb: 2 }}>
                    Top Queried Domains
                  </Typography>
                  <Typography sx={{ color: '#FFC700' }}>
                    Domain analytics coming soon...
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card sx={{ height: 400 }}>
                <CardContent>
                  <Typography variant="h6" sx={{ color: '#FFD700', mb: 2 }}>
                    Query Distribution by Type
                  </Typography>
                  <Typography sx={{ color: '#FFC700' }}>
                    Record type analytics coming soon...
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" sx={{ color: '#FFD700', mb: 2 }}>
                    Performance Metrics
                  </Typography>
                  <Typography sx={{ color: '#FFC700' }}>
                    Detailed performance metrics coming soon...
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Box>
      </Box>
    </Box>
  );
}
