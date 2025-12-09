import { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  IconButton,
  Tooltip,
  Chip,
  Alert,
  Typography,
} from '@mui/material';
import { DataGrid, GridColDef } from '@mui/x-data-grid';
import { Add, Delete, ContentCopy } from '@mui/icons-material';
import api from '../../services/api';
import { DNSServer } from '../../types';

export default function DNSServers() {
  const [servers, setServers] = useState<DNSServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [openDialog, setOpenDialog] = useState(false);
  const [joinKey, setJoinKey] = useState<string | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    serverUrl: '',
  });

  useEffect(() => {
    fetchServers();
  }, []);

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

  const handleOpenDialog = () => {
    setFormData({
      name: '',
      serverUrl: '',
    });
    setJoinKey(null);
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setJoinKey(null);
  };

  const handleRegister = async () => {
    try {
      const response = await api.post('/api/v1/dns-servers/register', formData);
      setJoinKey(response.data.joinKey);
      fetchServers();
    } catch (error) {
      console.error('Failed to register DNS server:', error);
    }
  };

  const handleDelete = async (id: number) => {
    if (confirm('Are you sure you want to remove this DNS server?')) {
      try {
        await api.delete(`/api/v1/dns-servers/${id}`);
        fetchServers();
      } catch (error) {
        console.error('Failed to delete DNS server:', error);
      }
    }
  };

  const handleCopyJoinKey = () => {
    if (joinKey) {
      navigator.clipboard.writeText(joinKey);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
        return 'success';
      case 'offline':
        return 'error';
      case 'degraded':
        return 'warning';
      default:
        return 'default';
    }
  };

  const columns: GridColDef[] = [
    { field: 'id', headerName: 'ID', width: 70 },
    { field: 'name', headerName: 'Server Name', flex: 1 },
    { field: 'serverUrl', headerName: 'Server URL', flex: 1 },
    {
      field: 'status',
      headerName: 'Status',
      width: 130,
      renderCell: (params) => (
        <Chip
          label={params.value.toUpperCase()}
          color={getStatusColor(params.value) as any}
          size="small"
        />
      ),
    },
    {
      field: 'lastHeartbeat',
      headerName: 'Last Heartbeat',
      width: 180,
      valueFormatter: (params) => {
        if (!params.value) return 'Never';
        return new Date(params.value).toLocaleString();
      },
    },
    { field: 'version', headerName: 'Version', width: 120 },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 80,
      sortable: false,
      renderCell: (params) => (
        <Tooltip title="Delete">
          <IconButton
            size="small"
            onClick={() => handleDelete(params.row.id)}
            sx={{ color: '#f44336' }}
          >
            <Delete />
          </IconButton>
        </Tooltip>
      ),
    },
  ];

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={handleOpenDialog}
          sx={{ backgroundColor: '#2C3E71', color: '#FFD700' }}
        >
          Register DNS Server
        </Button>
      </Box>

      <DataGrid
        rows={servers}
        columns={columns}
        loading={loading}
        autoHeight
        pageSizeOptions={[10, 25, 50]}
        initialState={{
          pagination: { paginationModel: { pageSize: 10 } },
        }}
        sx={{
          backgroundColor: '#2C3E50',
          '& .MuiDataGrid-row:hover': {
            backgroundColor: '#34495E',
          },
        }}
      />

      <Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ color: '#FFD700', backgroundColor: '#2C3E50' }}>
          Register DNS Server
        </DialogTitle>
        <DialogContent sx={{ backgroundColor: '#2C3E50', pt: 3 }}>
          {!joinKey ? (
            <>
              <TextField
                fullWidth
                label="Server Name"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                margin="normal"
                required
              />
              <TextField
                fullWidth
                label="Server URL"
                value={formData.serverUrl}
                onChange={(e) => setFormData({ ...formData, serverUrl: e.target.value })}
                margin="normal"
                required
                helperText="e.g., https://dns.example.com"
              />
            </>
          ) : (
            <Alert
              severity="success"
              sx={{
                backgroundColor: '#2C3E50',
                border: '1px solid #4CAF50',
                color: '#FFD700',
              }}
              action={
                <IconButton
                  size="small"
                  onClick={handleCopyJoinKey}
                  sx={{ color: '#FFD700' }}
                >
                  <ContentCopy />
                </IconButton>
              }
            >
              <Typography variant="body2" sx={{ mb: 2 }}>
                Server registered successfully! Use this join key to configure your DNS server:
              </Typography>
              <Typography
                variant="body1"
                sx={{
                  fontFamily: 'monospace',
                  backgroundColor: '#34495E',
                  p: 2,
                  borderRadius: 1,
                  wordBreak: 'break-all',
                }}
              >
                {joinKey}
              </Typography>
              <Typography variant="caption" sx={{ mt: 2, display: 'block' }}>
                Set this as MANAGER_JOIN_KEY in your DNS server environment variables.
              </Typography>
            </Alert>
          )}
        </DialogContent>
        <DialogActions sx={{ backgroundColor: '#2C3E50', p: 2 }}>
          <Button onClick={handleCloseDialog} sx={{ color: '#FFC700' }}>
            {joinKey ? 'Close' : 'Cancel'}
          </Button>
          {!joinKey && (
            <Button
              onClick={handleRegister}
              variant="contained"
              sx={{ backgroundColor: '#2C3E71', color: '#FFD700' }}
              disabled={!formData.name || !formData.serverUrl}
            >
              Register
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  );
}
