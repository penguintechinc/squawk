import { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  IconButton,
  Tooltip,
  Chip,
} from '@mui/material';
import { DataGrid, GridColDef } from '@mui/x-data-grid';
import { Add, Edit, Delete, List } from '@mui/icons-material';
import api from '../../services/api';
import { DNSZone, Team } from '../../types';

export default function Zones() {
  const [zones, setZones] = useState<DNSZone[]>([]);
  const [teams, setTeams] = useState<Team[]>([]);
  const [loading, setLoading] = useState(true);
  const [openDialog, setOpenDialog] = useState(false);
  const [editingZone, setEditingZone] = useState<DNSZone | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    teamId: 0,
    visibility: 'PUBLIC',
  });

  useEffect(() => {
    fetchZones();
    fetchTeams();
  }, []);

  const fetchZones = async () => {
    try {
      const response = await api.get<DNSZone[]>('/api/v1/dns-zones');
      setZones(response.data);
    } catch (error) {
      console.error('Failed to fetch DNS zones:', error);
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

  const handleOpenDialog = (zone?: DNSZone) => {
    if (zone) {
      setEditingZone(zone);
      setFormData({
        name: zone.name,
        teamId: zone.teamId,
        visibility: zone.visibility,
      });
    } else {
      setEditingZone(null);
      setFormData({
        name: '',
        teamId: teams[0]?.id || 0,
        visibility: 'PUBLIC',
      });
    }
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setEditingZone(null);
  };

  const handleSave = async () => {
    try {
      if (editingZone) {
        await api.put(`/api/v1/dns-zones/${editingZone.id}`, formData);
      } else {
        await api.post('/api/v1/dns-zones', formData);
      }
      handleCloseDialog();
      fetchZones();
    } catch (error) {
      console.error('Failed to save DNS zone:', error);
    }
  };

  const handleDelete = async (id: number) => {
    if (confirm('Are you sure you want to delete this DNS zone?')) {
      try {
        await api.delete(`/api/v1/dns-zones/${id}`);
        fetchZones();
      } catch (error) {
        console.error('Failed to delete DNS zone:', error);
      }
    }
  };

  const getVisibilityColor = (visibility: string) => {
    switch (visibility) {
      case 'PUBLIC':
        return 'success';
      case 'INTERNAL':
        return 'info';
      case 'RESTRICTED':
        return 'warning';
      case 'PRIVATE':
        return 'error';
      default:
        return 'default';
    }
  };

  const columns: GridColDef[] = [
    { field: 'id', headerName: 'ID', width: 70 },
    { field: 'name', headerName: 'Zone Name', flex: 1 },
    { field: 'teamName', headerName: 'Team', width: 200 },
    {
      field: 'visibility',
      headerName: 'Visibility',
      width: 150,
      renderCell: (params) => (
        <Chip
          label={params.value}
          color={getVisibilityColor(params.value) as any}
          size="small"
        />
      ),
    },
    {
      field: 'recordCount',
      headerName: 'Records',
      width: 100,
      valueFormatter: (params) => params.value || 0,
    },
    {
      field: 'createdAt',
      headerName: 'Created',
      width: 180,
      valueFormatter: (params) => new Date(params.value).toLocaleString(),
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 150,
      sortable: false,
      renderCell: (params) => (
        <Box>
          <Tooltip title="Manage Records">
            <IconButton
              size="small"
              onClick={() => window.location.href = `/zones/${params.row.id}/records`}
              sx={{ color: '#2196f3' }}
            >
              <List />
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
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => handleOpenDialog()}
          sx={{ backgroundColor: '#2C3E71', color: '#FFD700' }}
        >
          Add DNS Zone
        </Button>
      </Box>

      <DataGrid
        rows={zones}
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
          {editingZone ? 'Edit DNS Zone' : 'Add DNS Zone'}
        </DialogTitle>
        <DialogContent sx={{ backgroundColor: '#2C3E50', pt: 3 }}>
          <TextField
            fullWidth
            label="Zone Name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            margin="normal"
            required
            helperText="e.g., example.com"
          />
          <FormControl fullWidth margin="normal">
            <InputLabel sx={{ color: '#FFC700' }}>Team</InputLabel>
            <Select
              value={formData.teamId}
              label="Team"
              onChange={(e) => setFormData({ ...formData, teamId: e.target.value as number })}
            >
              {teams.map((team) => (
                <MenuItem key={team.id} value={team.id}>
                  {team.name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl fullWidth margin="normal">
            <InputLabel sx={{ color: '#FFC700' }}>Visibility</InputLabel>
            <Select
              value={formData.visibility}
              label="Visibility"
              onChange={(e) => setFormData({ ...formData, visibility: e.target.value })}
            >
              <MenuItem value="PUBLIC">Public - Visible to all users</MenuItem>
              <MenuItem value="INTERNAL">Internal - Visible to internal groups</MenuItem>
              <MenuItem value="RESTRICTED">Restricted - Visible to specific groups</MenuItem>
              <MenuItem value="PRIVATE">Private - Visible to admins only</MenuItem>
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions sx={{ backgroundColor: '#2C3E50', p: 2 }}>
          <Button onClick={handleCloseDialog} sx={{ color: '#FFC700' }}>
            Cancel
          </Button>
          <Button
            onClick={handleSave}
            variant="contained"
            sx={{ backgroundColor: '#2C3E71', color: '#FFD700' }}
          >
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
