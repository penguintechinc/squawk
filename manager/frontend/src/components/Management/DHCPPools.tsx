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
  LinearProgress,
  Typography,
} from '@mui/material';
import { DataGrid, GridColDef } from '@mui/x-data-grid';
import { Add, Edit, Delete, Storage } from '@mui/icons-material';
import api from '../../services/api';
import { DHCPPool, Team } from '../../types';

export default function DHCPPools() {
  const [pools, setPools] = useState<DHCPPool[]>([]);
  const [teams, setTeams] = useState<Team[]>([]);
  const [loading, setLoading] = useState(true);
  const [openDialog, setOpenDialog] = useState(false);
  const [editingPool, setEditingPool] = useState<DHCPPool | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    network: '',
    rangeStart: '',
    rangeEnd: '',
    gateway: '',
    dnsServers: '',
    ntpServers: '',
    domainName: '',
    leaseDuration: 86400,
    teamId: '' as string | number,
    active: true,
    enableDdns: false,
  });

  useEffect(() => {
    fetchPools();
    fetchTeams();
  }, []);

  const fetchPools = async () => {
    try {
      const response = await api.get<DHCPPool[]>('/api/v1/dhcp/pools');
      setPools(response.data);
    } catch (error) {
      console.error('Failed to fetch DHCP pools:', error);
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

  const handleOpenDialog = (pool?: DHCPPool) => {
    if (pool) {
      setEditingPool(pool);
      setFormData({
        name: pool.name,
        network: pool.network,
        rangeStart: pool.rangeStart,
        rangeEnd: pool.rangeEnd,
        gateway: pool.gateway || '',
        dnsServers: pool.dnsServers.join(', '),
        ntpServers: pool.ntpServers.join(', '),
        domainName: pool.domainName || '',
        leaseDuration: pool.leaseDuration,
        teamId: pool.teamId || '',
        active: pool.active,
        enableDdns: pool.enableDdns,
      });
    } else {
      setEditingPool(null);
      setFormData({
        name: '',
        network: '',
        rangeStart: '',
        rangeEnd: '',
        gateway: '',
        dnsServers: '',
        ntpServers: '',
        domainName: '',
        leaseDuration: 86400,
        teamId: '',
        active: true,
        enableDdns: false,
      });
    }
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setEditingPool(null);
  };

  const handleSave = async () => {
    try {
      const payload = {
        name: formData.name,
        network: formData.network,
        rangeStart: formData.rangeStart,
        rangeEnd: formData.rangeEnd,
        gateway: formData.gateway || null,
        dnsServers: formData.dnsServers.split(',').map(s => s.trim()).filter(Boolean),
        ntpServers: formData.ntpServers.split(',').map(s => s.trim()).filter(Boolean),
        domainName: formData.domainName || null,
        leaseDuration: formData.leaseDuration,
        teamId: formData.teamId || null,
        active: formData.active,
        enableDdns: formData.enableDdns,
      };

      if (editingPool) {
        await api.put(`/api/v1/dhcp/pools/${editingPool.id}`, payload);
      } else {
        await api.post('/api/v1/dhcp/pools', payload);
      }
      handleCloseDialog();
      fetchPools();
    } catch (error) {
      console.error('Failed to save DHCP pool:', error);
    }
  };

  const handleDelete = async (id: number) => {
    if (confirm('Are you sure you want to delete this DHCP pool? All leases and reservations will be removed.')) {
      try {
        await api.delete(`/api/v1/dhcp/pools/${id}`);
        fetchPools();
      } catch (error) {
        console.error('Failed to delete DHCP pool:', error);
      }
    }
  };

  const formatLeaseDuration = (seconds: number): string => {
    if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    return `${Math.round(seconds / 86400)} days`;
  };

  const columns: GridColDef[] = [
    { field: 'id', headerName: 'ID', width: 70 },
    { field: 'name', headerName: 'Pool Name', flex: 1 },
    { field: 'network', headerName: 'Network', width: 150 },
    {
      field: 'range',
      headerName: 'IP Range',
      width: 200,
      valueGetter: (params) => `${params.row.rangeStart} - ${params.row.rangeEnd}`,
    },
    {
      field: 'utilization',
      headerName: 'Utilization',
      width: 150,
      renderCell: (params) => {
        const active = params.row.activeLeases || 0;
        const reserved = params.row.reservedIps || 0;
        const total = active + reserved;
        const percent = params.row.statistics?.utilizationPercent || 0;
        return (
          <Box sx={{ width: '100%', display: 'flex', alignItems: 'center', gap: 1 }}>
            <LinearProgress
              variant="determinate"
              value={percent}
              sx={{
                width: 80,
                height: 8,
                borderRadius: 1,
                backgroundColor: '#34495E',
                '& .MuiLinearProgress-bar': {
                  backgroundColor: percent > 80 ? '#f44336' : percent > 50 ? '#ff9800' : '#4CAF50',
                },
              }}
            />
            <Typography variant="caption" sx={{ color: '#FFD700' }}>
              {total} used
            </Typography>
          </Box>
        );
      },
    },
    {
      field: 'leaseDuration',
      headerName: 'Lease',
      width: 100,
      valueFormatter: (params) => formatLeaseDuration(params.value),
    },
    {
      field: 'active',
      headerName: 'Status',
      width: 100,
      renderCell: (params) => (
        <Chip
          label={params.value ? 'ACTIVE' : 'INACTIVE'}
          color={params.value ? 'success' : 'default'}
          size="small"
        />
      ),
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 120,
      sortable: false,
      renderCell: (params) => (
        <Box>
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
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => handleOpenDialog()}
          sx={{ backgroundColor: '#2C3E71', color: '#FFD700' }}
        >
          Add DHCP Pool
        </Button>
      </Box>

      <DataGrid
        rows={pools}
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

      <Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="md" fullWidth>
        <DialogTitle sx={{ color: '#FFD700', backgroundColor: '#2C3E50' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Storage />
            {editingPool ? 'Edit DHCP Pool' : 'Add DHCP Pool'}
          </Box>
        </DialogTitle>
        <DialogContent sx={{ backgroundColor: '#2C3E50', pt: 3 }}>
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
            <TextField
              fullWidth
              label="Pool Name"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              margin="normal"
              required
            />
            <TextField
              fullWidth
              label="Network (CIDR)"
              value={formData.network}
              onChange={(e) => setFormData({ ...formData, network: e.target.value })}
              margin="normal"
              required
              helperText="e.g., 192.168.1.0/24"
            />
            <TextField
              fullWidth
              label="Range Start"
              value={formData.rangeStart}
              onChange={(e) => setFormData({ ...formData, rangeStart: e.target.value })}
              margin="normal"
              required
              helperText="e.g., 192.168.1.100"
            />
            <TextField
              fullWidth
              label="Range End"
              value={formData.rangeEnd}
              onChange={(e) => setFormData({ ...formData, rangeEnd: e.target.value })}
              margin="normal"
              required
              helperText="e.g., 192.168.1.200"
            />
            <TextField
              fullWidth
              label="Gateway"
              value={formData.gateway}
              onChange={(e) => setFormData({ ...formData, gateway: e.target.value })}
              margin="normal"
              helperText="e.g., 192.168.1.1"
            />
            <TextField
              fullWidth
              label="Domain Name"
              value={formData.domainName}
              onChange={(e) => setFormData({ ...formData, domainName: e.target.value })}
              margin="normal"
              helperText="e.g., office.local"
            />
            <TextField
              fullWidth
              label="DNS Servers"
              value={formData.dnsServers}
              onChange={(e) => setFormData({ ...formData, dnsServers: e.target.value })}
              margin="normal"
              helperText="Comma-separated IPs"
            />
            <TextField
              fullWidth
              label="NTP Servers"
              value={formData.ntpServers}
              onChange={(e) => setFormData({ ...formData, ntpServers: e.target.value })}
              margin="normal"
              helperText="Comma-separated IPs or hostnames"
            />
            <TextField
              fullWidth
              label="Lease Duration (seconds)"
              type="number"
              value={formData.leaseDuration}
              onChange={(e) => setFormData({ ...formData, leaseDuration: parseInt(e.target.value) || 86400 })}
              margin="normal"
              helperText={`= ${formatLeaseDuration(formData.leaseDuration)}`}
            />
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
          </Box>
          <Box sx={{ mt: 2, display: 'flex', gap: 3 }}>
            <FormControlLabel
              control={
                <Switch
                  checked={formData.active}
                  onChange={(e) => setFormData({ ...formData, active: e.target.checked })}
                />
              }
              label="Active"
            />
            <FormControlLabel
              control={
                <Switch
                  checked={formData.enableDdns}
                  onChange={(e) => setFormData({ ...formData, enableDdns: e.target.checked })}
                />
              }
              label="Enable Dynamic DNS"
            />
          </Box>
        </DialogContent>
        <DialogActions sx={{ backgroundColor: '#2C3E50', p: 2 }}>
          <Button onClick={handleCloseDialog} sx={{ color: '#FFC700' }}>
            Cancel
          </Button>
          <Button
            onClick={handleSave}
            variant="contained"
            sx={{ backgroundColor: '#2C3E71', color: '#FFD700' }}
            disabled={!formData.name || !formData.network || !formData.rangeStart || !formData.rangeEnd}
          >
            {editingPool ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
