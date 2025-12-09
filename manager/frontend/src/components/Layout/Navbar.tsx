import { AppBar, Toolbar, Typography, IconButton, Menu, MenuItem, Box, Avatar } from '@mui/material';
import { AccountCircle, Logout, Settings } from '@mui/icons-material';
import { useState } from 'react';
import { useAuth } from '../../hooks/useAuth';

export default function Navbar() {
  const { user, logout } = useAuth();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  const handleMenu = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = () => {
    handleClose();
    logout();
  };

  return (
    <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
      <Toolbar>
        <Box sx={{ display: 'flex', alignItems: 'center', flexGrow: 1 }}>
          <Box
            component="img"
            src="/squawk-logo.png"
            alt="Squawk DNS"
            sx={{
              height: 40,
              mr: 2,
              // Fallback if image doesn't exist
              display: { xs: 'none', sm: 'block' }
            }}
            onError={(e) => {
              (e.target as HTMLElement).style.display = 'none';
            }}
          />
          <Typography
            variant="h6"
            noWrap
            component="div"
            sx={{
              fontWeight: 700,
              color: '#FFD700',
              letterSpacing: '0.5px',
            }}
          >
            Squawk DNS Manager
          </Typography>
        </Box>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Typography variant="body2" sx={{ color: '#FFC700' }}>
            {user?.username || 'User'}
          </Typography>
          <Typography variant="caption" sx={{ color: '#FFC700', opacity: 0.8 }}>
            {user?.globalRole || 'Role'}
          </Typography>

          <IconButton
            size="large"
            aria-label="account menu"
            aria-controls="menu-appbar"
            aria-haspopup="true"
            onClick={handleMenu}
            sx={{ color: '#FFD700' }}
          >
            <Avatar sx={{ bgcolor: '#2C3E71', color: '#FFD700', width: 32, height: 32 }}>
              <AccountCircle />
            </Avatar>
          </IconButton>
          <Menu
            id="menu-appbar"
            anchorEl={anchorEl}
            anchorOrigin={{
              vertical: 'bottom',
              horizontal: 'right',
            }}
            keepMounted
            transformOrigin={{
              vertical: 'top',
              horizontal: 'right',
            }}
            open={Boolean(anchorEl)}
            onClose={handleClose}
            PaperProps={{
              sx: {
                backgroundColor: '#2C3E50',
                border: '1px solid #34495E',
              }
            }}
          >
            <MenuItem onClick={handleClose}>
              <Settings sx={{ mr: 1, color: '#FFD700' }} />
              <Typography sx={{ color: '#FFD700' }}>Settings</Typography>
            </MenuItem>
            <MenuItem onClick={handleLogout}>
              <Logout sx={{ mr: 1, color: '#FFD700' }} />
              <Typography sx={{ color: '#FFD700' }}>Logout</Typography>
            </MenuItem>
          </Menu>
        </Box>
      </Toolbar>
    </AppBar>
  );
}
