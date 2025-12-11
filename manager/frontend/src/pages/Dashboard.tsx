import { Box, Toolbar, Grid } from '@mui/material';
import Navbar from '../components/Layout/Navbar';
import Sidebar from '../components/Layout/Sidebar';
import StatsOverview from '../components/Dashboard/StatsOverview';
import QueryChart from '../components/Dashboard/QueryChart';
import DNSServerFleet from '../components/Dashboard/DNSServerFleet';

export default function Dashboard() {
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
        <Grid container spacing={3} sx={{ mt: 1 }}>
          <Grid item xs={12}>
            <StatsOverview />
          </Grid>
          <Grid item xs={12}>
            <DNSServerFleet />
          </Grid>
          <Grid item xs={12}>
            <QueryChart />
          </Grid>
        </Grid>
      </Box>
    </Box>
  );
}
