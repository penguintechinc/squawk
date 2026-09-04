import { useState } from 'react';
import { Box, Toolbar, Tabs, Tab, Typography } from '@mui/material';
import Navbar from '../components/Layout/Navbar';
import Sidebar from '../components/Layout/Sidebar';
import Users from '../components/Management/Users';
import Teams from '../components/Management/Teams';
import DNSServers from '../components/Management/DNSServers';
import Zones from '../components/Management/Zones';
import DHCPPools from '../components/Management/DHCPPools';
import TimeServers from '../components/Management/TimeServers';
import { usePermissions } from '../hooks/usePermissions';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`management-tabpanel-${index}`}
      aria-labelledby={`management-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
}

export default function Management() {
  const permissions = usePermissions();
  const [currentTab, setCurrentTab] = useState(0);

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setCurrentTab(newValue);
  };

  const tabs = [
    {
      label: 'DNS Servers',
      component: <DNSServers />,
      visible: permissions.canManageServers(),
    },
    {
      label: 'DNS Zones',
      component: <Zones />,
      visible: permissions.canManageZones(),
    },
    {
      label: 'DHCP Pools',
      component: <DHCPPools />,
      visible: permissions.canManageServers(),
    },
    {
      label: 'Time Servers',
      component: <TimeServers />,
      visible: permissions.canManageServers(),
    },
    {
      label: 'Users',
      component: <Users />,
      visible: permissions.canManageUsers(),
    },
    {
      label: 'Teams',
      component: <Teams />,
      visible: permissions.canManageTeams(),
    },
  ];

  const visibleTabs = tabs.filter((tab) => tab.visible);

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
            Management
          </Typography>

          {visibleTabs.length === 0 ? (
            <Typography sx={{ color: '#FFC700', textAlign: 'center', mt: 8 }}>
              You don't have permission to manage any resources.
            </Typography>
          ) : (
            <>
              <Box sx={{ borderBottom: 1, borderColor: '#34495E' }}>
                <Tabs
                  value={currentTab}
                  onChange={handleTabChange}
                  TabIndicatorProps={{
                    style: { backgroundColor: '#FFD700' },
                  }}
                >
                  {visibleTabs.map((tab, index) => (
                    <Tab
                      key={index}
                      label={tab.label}
                      sx={{
                        color: '#FFC700',
                        '&.Mui-selected': {
                          color: '#FFD700',
                        },
                      }}
                    />
                  ))}
                </Tabs>
              </Box>

              {visibleTabs.map((tab, index) => (
                <TabPanel key={index} value={currentTab} index={index}>
                  {tab.component}
                </TabPanel>
              ))}
            </>
          )}
        </Box>
      </Box>
    </Box>
  );
}
