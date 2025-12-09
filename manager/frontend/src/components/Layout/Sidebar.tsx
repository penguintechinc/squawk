import {
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
  Divider,
  Box,
} from '@mui/material';
import {
  Dashboard,
  Dns,
  People,
  Groups,
  Language,
  Analytics,
  Settings,
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import { usePermissions } from '../../hooks/usePermissions';

const drawerWidth = 260;

interface MenuItem {
  title: string;
  icon: React.ReactNode;
  path: string;
  permission?: () => boolean;
}

export default function Sidebar() {
  const navigate = useNavigate();
  const location = useLocation();
  const permissions = usePermissions();

  const menuItems: MenuItem[] = [
    {
      title: 'Dashboard',
      icon: <Dashboard />,
      path: '/',
    },
    {
      title: 'DNS Servers',
      icon: <Dns />,
      path: '/servers',
      permission: permissions.canManageServers,
    },
    {
      title: 'Users',
      icon: <People />,
      path: '/users',
      permission: permissions.canManageUsers,
    },
    {
      title: 'Teams',
      icon: <Groups />,
      path: '/teams',
      permission: permissions.canManageTeams,
    },
    {
      title: 'DNS Zones',
      icon: <Language />,
      path: '/zones',
      permission: permissions.canManageZones,
    },
    {
      title: 'Analytics',
      icon: <Analytics />,
      path: '/analytics',
      permission: permissions.canViewAnalytics,
    },
  ];

  const handleNavigation = (path: string) => {
    navigate(path);
  };

  return (
    <Drawer
      variant="permanent"
      sx={{
        width: drawerWidth,
        flexShrink: 0,
        '& .MuiDrawer-paper': {
          width: drawerWidth,
          boxSizing: 'border-box',
          backgroundColor: '#2C3E50',
          borderRight: '1px solid #34495E',
        },
      }}
    >
      <Toolbar />
      <Box sx={{ overflow: 'auto', mt: 2 }}>
        <List>
          {menuItems
            .filter((item) => !item.permission || item.permission())
            .map((item) => (
              <ListItem key={item.title} disablePadding sx={{ mb: 0.5 }}>
                <ListItemButton
                  selected={location.pathname === item.path}
                  onClick={() => handleNavigation(item.path)}
                  sx={{
                    mx: 1,
                    borderRadius: 2,
                    '&.Mui-selected': {
                      backgroundColor: '#2C3E71',
                      '&:hover': {
                        backgroundColor: '#1a2642',
                      },
                    },
                    '&:hover': {
                      backgroundColor: '#34495E',
                    },
                  }}
                >
                  <ListItemIcon sx={{ color: '#FFD700', minWidth: 40 }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.title}
                    primaryTypographyProps={{
                      sx: {
                        color: '#FFD700',
                        fontWeight: location.pathname === item.path ? 600 : 400,
                      },
                    }}
                  />
                </ListItemButton>
              </ListItem>
            ))}
        </List>

        <Divider sx={{ my: 2, backgroundColor: '#34495E' }} />

        <List>
          <ListItem disablePadding sx={{ mb: 0.5 }}>
            <ListItemButton
              onClick={() => handleNavigation('/settings')}
              sx={{
                mx: 1,
                borderRadius: 2,
                '&:hover': {
                  backgroundColor: '#34495E',
                },
              }}
            >
              <ListItemIcon sx={{ color: '#FFD700', minWidth: 40 }}>
                <Settings />
              </ListItemIcon>
              <ListItemText
                primary="Settings"
                primaryTypographyProps={{
                  sx: { color: '#FFD700' },
                }}
              />
            </ListItemButton>
          </ListItem>
        </List>
      </Box>
    </Drawer>
  );
}
