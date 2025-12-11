import { createTheme } from '@mui/material/styles';

export const squawkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#2C3E71',      // Navy blue
      dark: '#1a2642',
      light: '#3d5294',
      contrastText: '#FFD700',
    },
    secondary: {
      main: '#34495E',      // Dark grey
      dark: '#2C3E50',
      light: '#546E7A',
      contrastText: '#FFD700',
    },
    text: {
      primary: '#FFD700',   // Gold
      secondary: '#FFC700',
    },
    background: {
      default: '#1a1a1a',
      paper: '#2C3E50',
    },
    success: {
      main: '#4CAF50',
      contrastText: '#FFD700',
    },
    error: {
      main: '#f44336',
      contrastText: '#FFD700',
    },
    warning: {
      main: '#ff9800',
      contrastText: '#FFD700',
    },
    info: {
      main: '#2196f3',
      contrastText: '#FFD700',
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
    h1: { color: '#FFD700', fontWeight: 700 },
    h2: { color: '#FFD700', fontWeight: 600 },
    h3: { color: '#FFD700', fontWeight: 600 },
    h4: { color: '#FFD700', fontWeight: 500 },
    h5: { color: '#FFD700', fontWeight: 500 },
    h6: { color: '#FFD700', fontWeight: 500 },
    body1: { color: '#FFD700' },
    body2: { color: '#FFC700' },
    button: { textTransform: 'none', fontWeight: 600 },
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          padding: '8px 24px',
        },
        contained: {
          backgroundColor: '#2C3E71',
          color: '#FFD700',
          '&:hover': {
            backgroundColor: '#1a2642',
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          backgroundColor: '#2C3E50',
          border: '1px solid #34495E',
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: '#2C3E71',
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: '#2C3E50',
          borderRight: '1px solid #34495E',
        },
      },
    },
    // MuiDataGrid requires @mui/x-data-grid type extensions
    // Styling will be handled via CSS or inline styles
    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            color: '#FFD700',
            '& fieldset': {
              borderColor: '#34495E',
            },
            '&:hover fieldset': {
              borderColor: '#FFD700',
            },
            '&.Mui-focused fieldset': {
              borderColor: '#FFD700',
            },
          },
          '& .MuiInputLabel-root': {
            color: '#FFC700',
          },
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundColor: '#2C3E50',
          color: '#FFD700',
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: {
          color: '#FFD700',
          borderBottom: '1px solid #34495E',
        },
        head: {
          backgroundColor: '#2C3E71',
          color: '#FFD700',
          fontWeight: 600,
        },
      },
    },
  },
});
