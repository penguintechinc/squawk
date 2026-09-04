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
  FormControlLabel,
  Switch,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Typography,
  Alert,
} from '@mui/material';
import { DataGrid, GridColDef } from '@mui/x-data-grid';
import { Add, Edit, Delete, Sync, Schedule } from '@mui/icons-material';
import api from '../../services/api';
import { TimeServer, Team, TimeStatus } from '../../types';

export default function TimeServers() {
  const [servers, setServers] = useState<TimeServer[]>([]);
  const [teams, setTeams] = useState<Team[]>([]);
  const [timeStatus, setTimeStatus] = useState<TimeStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [openDialog, setOpenDialog] = useState(false);
  const [editingServer, setEditingServer] = useState<TimeServer | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    serverUrl: '',
    protocol: 'ntp' as 'ptp' | 'ntp',
    stratum: 2,
    priority: 100,
    teamId: '' as string | number,
    active: true,
    ptpDomain: 0,
  });

  useEffect(() => {
    fetchServers();
    fetchTeams();
    fetchTimeStatus();
  }, []);

  const fetchServers = async () => {
    try {
      const response = await api.get<TimeServer[]>('/api/v1/time/servers');
      setServers(response.data);
    } catch (error) {
      console.error('Failed to fetch time servers:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchTeams = async () => {
    try {
      const response = await api.get<Team[]>('/api/v1/teams');
      setTeams(response.data);
    } catch (error) {
      console.error('Failed to fetch teams:', error);
    }
  };

  const fetchTimeStatus = async () => {
    try {
      const response = await api.get<TimeStatus>('/api/v1/time/status');
      setTimeStatus(response.data);
    } catch (error) {
      console.error('Failed to fetch time status:', error);
    }
  };

  const handleOpenDialog = (server?: TimeServer) => {
    if (server) {
      setEditingServer(server);
      setFormData({
        name: server.name,
        serverUrl: server.serverUrl,
        protocol: server.protocol,
        stratum: server.stratum,
        priority: server.priority,
        teamId: server.teamId || '',
        active: server.active,
        ptpDomain: server.ptpConfig?.domain || 0,
      });
    } else {
      setEditingServer(null);
      setFormData({
        name: '',
        serverUrl: '',
        protocol: 'ntp',
        stratum: 2,
        priority: 100,
        teamId: '',
        active: true,
        ptpDomain: 0,
      });
    }
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setEditingServer(null);
  };

  const handleSave = async () => {
    try {
      const payload: any = {
        name: formData.name,
        serverUrl: formData.serverUrl,
        protocol: formData.protocol,
        stratum: formData.stratum,
        priority: formData.priority,
        teamId: formData.teamId || null,
        active: formData.active,
      };

      if (formData.protocol === 'ptp') {
        payload.ptpConfig = {
          domain: formData.ptpDomain,
          transport: 'udp',
          delayMechanism: 'e2e',
        };
      }

      if (editingServer) {
        await api.put(`/api/v1/time/servers/${editingServer.id}`, payload);
      } else {
        await api.post('/api/v1/time/servers', payload);
      }
      handleCloseDialog();
      fetchServers();
    } catch (error) {
      console.error('Failed to save time server:', error);
    }
  };

  const handleDelete = async (id: number) => {
    if (confirm('Are you sure you want to delete this time server?')) {
      try {
        await api.delete(`/api/v1/time/servers/${id}`);
        fetchServers();
      } catch (error) {
        console.error('Failed to delete time server:', error);
      }
    }
  };

  const handleSync = async (serverId?: number) => {
    setSyncing(true);
    try {
      const payload = serverId ? { serverId } : {};
      await api.post('/api/v1/time/sync', payload);
      fetchServers();
      fetchTimeStatus();
    } catch (error) {
      console.error('Failed to sync time:', error);
    } finally {
      setSyncing(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'synchronized':
        return 'success';
      case 'unsynchronized':
        return 'warning';
      case 'unreachable':
        return 'error';
      default:
        return 'default';
    }
  };

  const getProtocolColor = (protocol: string) => {
    return protocol === 'ptp' ? 'primary' : 'secondary';
  };

  const formatOffset = (ms?: number): string => {
    if (ms === undefined || ms === null) return '-';
    if (Math.abs(ms) < 0.001) return '<0.001 ms';
    if (Math.abs(ms) < 1) return `${ms.toFixed(4)} ms`;
    return `${ms.toFixed(2)} ms`;
  };

  const columns: GridColDef[] = [
    { field: 'id', headerName: 'ID', width: 70 },
    { field: 'name', headerName: 'Server Name', flex: 1 },
    { field: 'serverUrl', headerName: 'Address', flex: 1 },
    {
      field: 'protocol',
      headerName: 'Protocol',
      width: 100,
      renderCell: (params) => (
        <Chip
          label={params.value.toUpperCase()}
          color={getProtocolColor(params.value) as any}
          size="small"
        />
      ),
    },
    { field: 'stratum', headerName: 'Stratum', width: 80 },
    { field: 'priority', headerName: 'Priority', width: 80 },
    {
      field: 'status',
      headerName: 'Status',
      width: 140,
      renderCell: (params) => (
        <Chip
          label={params.value.toUpperCase()}
          color={getStatusColor(params.value) as any}
          size="small"
        />
      ),
    },
    {
      field: 'lastOffsetMs',
      headerName: 'Offset',
      width: 120,
      valueFormatter: (params) => formatOffset(params.value),
    },
    {
      field: 'lastSync',
      headerName: 'Last Sync',
      width: 160,
      valueFormatter: (params) => {
        if (!params.value) return 'Never';
        return new Date(params.value).toLocaleString();
      },
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 150,
      sortable: false,
      renderCell: (params) => (
        <Box>
          <Tooltip title="Sync Now">
            <IconButton
              size="small"
              onClick={() => handleSync(params.row.id)}
              sx={{ color: '#4CAF50' }}
              disabled={syncing || !params.row.active}
            >
              <Sync />
            </IconButton>
          </Tooltip>
          <Tooltip title="Edit">
            <IconButton
              size="small"
              onClick={() => handleOpenDialog(params.row)}
              sx={{ color: '#FFD700' }}
            >
              <Edit />
            </IconButton>
          </Tooltip>
          <Tooltip title="Delete">
            <IconButton
              size="small"
              onClick={() => handleDelete(params.row.id)}
              sx={{ color: '#f44336' }}
            >
              <Delete />
            </IconButton>
          </Tooltip>
        </Box>
      ),
    },
  ];

  return (
    <Box>
      {/* Time Status Banner */}
      {timeStatus && (
        <Alert
          severity={timeStatus.synchronized ? 'success' : 'warning'}
          sx={{
            mb: 3,
            backgroundColor: '#2C3E50',
            border: `1px solid ${timeStatus.synchronized ? '#4CAF50' : '#ff9800'}`,
            color: '#FFD700',
          }}
          icon={<Schedule sx={{ color: timeStatus.synchronized ? '#4CAF50' : '#ff9800' }} />}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Typography variant="body2">
              <strong>System Time:</strong> {timeStatus.synchronized ? 'Synchronized' : 'Not Synchronized'}
            </Typography>
            {timeStatus.activeSource && (
              <Typography variant="body2">
                <strong>Source:</strong> {timeStatus.activeSource.name} ({timeStatus.activeSource.protocol.toUpperCase()})
              </Typography>
            )}
            {timeStatus.offsetMs !== undefined && (
              <Typography variant="body2">
                <strong>Offset:</strong> {formatOffset(timeStatus.offsetMs)}
              </Typography>
            )}
          </Box>
        </Alert>
      )}

      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => handleOpenDialog()}
          sx={{ backgroundColor: '#2C3E71', color: '#FFD700' }}
        >
          Add Time Server
        </Button>
        <Button
          variant="outlined"
          startIcon={<Sync />}
          onClick={() => handleSync()}
          disabled={syncing}
          sx={{ borderColor: '#4CAF50', color: '#4CAF50' }}
        >
          {syncing ? 'Syncing...' : 'Sync All'}
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
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Schedule />
            {editingServer ? 'Edit Time Server' : 'Add Time Server'}
          </Box>
        </DialogTitle>
        <DialogContent sx={{ backgroundColor: '#2C3E50', pt: 3 }}>
          <TextField
            fullWidth
            label="Server Name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            margin="normal"
            required
          />
          <FormControl fullWidth margin="normal">
            <InputLabel>Protocol</InputLabel>
            <Select
              value={formData.protocol}
              onChange={(e) => setFormData({ ...formData, protocol: e.target.value as 'ptp' | 'ntp' })}
              label="Protocol"
            >
              <MenuItem value="ptp">PTP (IEEE 1588) - Microsecond Accuracy</MenuItem>
              <MenuItem value="ntp">NTP v4 - Millisecond Accuracy</MenuItem>
            </Select>
          </FormControl>
          <TextField
            fullWidth
            label="Server Address"
            value={formData.serverUrl}
            onChange={(e) => setFormData({ ...formData, serverUrl: e.target.value })}
            margin="normal"
            required
            helperText={formData.protocol === 'ptp' ? 'e.g., ptp://192.168.1.1' : 'e.g., ntp://time.google.com'}
          />
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
            <TextField
              fullWidth
              label="Stratum"
              type="number"
              value={formData.stratum}
              onChange={(e) => setFormData({ ...formData, stratum: parseInt(e.target.value) || 2 })}
              margin="normal"
              inputProps={{ min: 1, max: 15 }}
              helperText="1 = Primary, 2-15 = Secondary"
            />
            <TextField
              fullWidth
              label="Priority"
              type="number"
              value={formData.priority}
              onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 100 })}
              margin="normal"
              inputProps={{ min: 1, max: 999 }}
              helperText="Lower = Higher priority"
            />
          </Box>
          {formData.protocol === 'ptp' && (
            <TextField
              fullWidth
              label="PTP Domain"
              type="number"
              value={formData.ptpDomain}
              onChange={(e) => setFormData({ ...formData, ptpDomain: parseInt(e.target.value) || 0 })}
              margin="normal"
              inputProps={{ min: 0, max: 127 }}
              helperText="PTP domain number (0-127)"
            />
          )}
          <FormControl fullWidth margin="normal">
            <InputLabel>Team</InputLabel>
            <Select
              value={formData.teamId}
              onChange={(e) => setFormData({ ...formData, teamId: e.target.value })}
              label="Team"
            >
              <MenuItem value="">None (Global)</MenuItem>
              {teams.map((team) => (
                <MenuItem key={team.id} value={team.id}>
                  {team.name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControlLabel
            control={
              <Switch
                checked={formData.active}
                onChange={(e) => setFormData({ ...formData, active: e.target.checked })}
              />
            }
            label="Active"
            sx={{ mt: 2 }}
          />
        </DialogContent>
        <DialogActions sx={{ backgroundColor: '#2C3E50', p: 2 }}>
          <Button onClick={handleCloseDialog} sx={{ color: '#FFC700' }}>
            Cancel
          </Button>
          <Button
            onClick={handleSave}
            variant="contained"
            sx={{ backgroundColor: '#2C3E71', color: '#FFD700' }}
            disabled={!formData.name || !formData.serverUrl}
          >
            {editingServer ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
