import React, { useState, useEffect } from 'react';
import {
  Container,
  Typography,
  Grid,
  Card,
  CardContent,
  Box,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Button,
  TextField,
  MenuItem,
  Alert,
  CircularProgress,
  IconButton,
  Tooltip
} from '@mui/material';
import {
  Wifi,
  Security,
  SignalWifi4Bar,
  SignalWifi3Bar,
  SignalWifi2Bar,
  SignalWifi1Bar,
  Refresh,
  Search,
  Shield,
  Warning,
  CheckCircle
} from '@mui/icons-material';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import axios from 'axios';
import { format, formatDistanceToNow } from 'date-fns';

interface Network {
  _id: string;
  ssid: string;
  bssid: string;
  rssi: number;
  channel: number;
  encType: string;
  firstSeen: string;
  lastSeen: string;
  seenCount: number;
  status: 'trusted' | 'unknown' | 'suspicious';
  deviceId: string;
  createdAt: string;
  updatedAt: string;
}

interface Stats {
  total: number;
  recentlyActive: number;
  trusted: number;
  unknown: number;
  suspicious: number;
}

interface Threat {
  networkId: string;
  ssid: string;
  bssid: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  harmScore: number;
  threats: Array<{
    type: string;
    severity: string;
    description: string;
    details: string;
  }>;
  recommendation: {
    general: string;
    specific: string[];
  };
  isHarmful: boolean;
  timestamp: string;
}

interface ThreatSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  harmful: number;
}

const API_BASE_URL = 'https://wifi-intrusion-backend.onrender.com/api';


const Dashboard: React.FC = () => {
  const [networks, setNetworks] = useState<Network[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [threatSummary, setThreatSummary] = useState<ThreatSummary | null>(null);
  const [showThreatsOnly, setShowThreatsOnly] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>('all');
  const [search, setSearch] = useState<string>('');
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  // Fetch data from backend
  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);

      const [networksResponse, statsResponse, threatsResponse] = await Promise.all([
        axios.get(`${API_BASE_URL}/networks?status=${filter}&search=${search}&limit=100`),
        axios.get(`${API_BASE_URL}/stats`),
        axios.get(`${API_BASE_URL}/threats`)
      ]);

      setNetworks(networksResponse.data.networks);
      setStats(statsResponse.data.stats);
      setThreats(threatsResponse.data.threats || []);
      setThreatSummary(threatsResponse.data.summary || null);
      setLastUpdate(new Date());
    } catch (err: any) {
      setError(err.message || 'Failed to fetch data');
      console.error('API Error:', err);
    } finally {
      setLoading(false);
    }
  };

  // Update network status
  const updateNetworkStatus = async (networkId: string, newStatus: 'trusted' | 'unknown' | 'suspicious') => {
    try {
      await axios.patch(`${API_BASE_URL}/networks/${networkId}/status`, {
        status: newStatus
      });
      
      // Update local state
      setNetworks(prev => prev.map(network => 
        network._id === networkId ? { ...network, status: newStatus } : network
      ));
      
      // Refresh stats
      fetchData();
    } catch (err: any) {
      setError(`Failed to update status: ${err.message}`);
    }
  };

  // Get signal strength icon
  const getSignalIcon = (rssi: number) => {
    if (rssi >= -50) return <SignalWifi4Bar color="success" />;
    if (rssi >= -65) return <SignalWifi3Bar color="warning" />;
    if (rssi >= -75) return <SignalWifi2Bar color="warning" />;
    return <SignalWifi1Bar color="error" />;
  };

  // Get status chip
  const getStatusChip = (status: string) => {
    const statusConfig = {
      trusted: { color: 'success' as const, icon: <CheckCircle fontSize="small" />, label: 'Trusted' },
      unknown: { color: 'default' as const, icon: <Wifi fontSize="small" />, label: 'Unknown' },
      suspicious: { color: 'error' as const, icon: <Warning fontSize="small" />, label: 'Suspicious' }
    };

    const config = statusConfig[status as keyof typeof statusConfig] || statusConfig.unknown;
    
    return (
      <Chip
        icon={config.icon}
        label={config.label}
        color={config.color}
        size="small"
      />
    );
  };

  // Auto-refresh every 30 seconds
  useEffect(() => {
    fetchData();
    
    const interval = setInterval(() => {
      fetchData();
    }, 30000);

    return () => clearInterval(interval);
  }, [filter, search]);

  // Chart data
  const chartData = networks.reduce((acc, network) => {
    const channel = String(network.channel);
    const existing = acc.find(item => item.channel === `Ch ${channel}`);
    if (existing) {
      existing.count += 1;
    } else {
      acc.push({ channel: `Ch ${channel}`, count: 1 });
    }
    return acc;
  }, [] as { channel: string; count: number }[]);

  const pieData = stats ? [
    { name: 'Trusted', value: stats.trusted, color: '#4caf50' },
    { name: 'Unknown', value: stats.unknown, color: '#9e9e9e' },
    { name: 'Suspicious', value: stats.suspicious, color: '#f44336' }
  ] : [];

  if (loading && networks.length === 0) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <CircularProgress size={60} />
      </Box>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={4}>
        <Typography variant="h4" component="h1" gutterBottom>
          <Shield sx={{ mr: 2, verticalAlign: 'middle' }} />
          WiFi Intrusion Detector
        </Typography>
        <Box>
          <Typography variant="body2" color="textSecondary" sx={{ mr: 2 }}>
            Last updated: {format(lastUpdate, 'HH:mm:ss')}
          </Typography>
          <IconButton onClick={fetchData} disabled={loading}>
            <Refresh />
          </IconButton>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Stats Cards */}
      {stats && (
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid size={{ xs: 12, sm: 6, md: 2 }}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>Total Networks</Typography>
                <Typography variant="h4">{stats.total}</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2 }}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>Recently Active</Typography>
                <Typography variant="h4" color="primary">{stats.recentlyActive}</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2 }}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>Trusted</Typography>
                <Typography variant="h4" color="success.main">{stats.trusted}</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2 }}>
            <Card sx={{ bgcolor: threatSummary?.harmful ? '#ffebee' : 'inherit' }}>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>Threats Detected</Typography>
                <Typography variant="h4" color="error.main">
                  {threats.length}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2 }}>
            <Card sx={{ bgcolor: threatSummary?.critical ? '#ffcdd2' : 'inherit' }}>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>Critical Threats</Typography>
                <Typography variant="h4" color="error.main">
                  {threatSummary?.critical || 0}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2 }}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>Suspicious</Typography>
                <Typography variant="h4" color="error.main">{stats.suspicious}</Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Threat Alerts */}
      {threats.length > 0 && (
        <Box mb={4}>
          <Alert 
            severity={threatSummary?.critical ? 'error' : threatSummary?.high ? 'warning' : 'info'}
            sx={{ mb: 2 }}
          >
            <Typography variant="h6" gutterBottom>
              🚨 Security Alert: {threats.length} potential threats detected
            </Typography>
            <Typography variant="body2">
              Critical: {threatSummary?.critical || 0} | 
              High: {threatSummary?.high || 0} | 
              Medium: {threatSummary?.medium || 0} | 
              Low: {threatSummary?.low || 0}
            </Typography>
          </Alert>

          {/* Show top 3 most critical threats */}
          {threats.slice(0, 3).map((threat, index) => (
            <Alert key={index} severity={threat.riskLevel === 'critical' || threat.riskLevel === 'high' ? 'error' : 'warning'} sx={{ mb: 1 }}>
              <Box>
                <Typography variant="subtitle2" fontWeight="bold">
                  🛡️ {threat.ssid} ({threat.bssid})
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Risk Level: {threat.riskLevel.toUpperCase()} (Score: {threat.harmScore}/100)
                </Typography>
                <Typography variant="body2">
                  {threat.threats.map(t => t.description).join('; ')}
                </Typography>
                <Typography variant="body2" sx={{ mt: 1, fontStyle: 'italic' }}>
                  💡 Recommendation: {threat.recommendation.general}
                </Typography>
              </Box>
            </Alert>
          ))}
        </Box>
      )}

      {/* Charts */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid size={{ xs: 12, md: 8 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>Networks by Channel</Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="channel" />
                  <YAxis />
                  <RechartsTooltip />
                  <Bar dataKey="count" fill="#1976d2" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, md: 4 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>Network Status Distribution</Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Filters */}
      <Box display="flex" gap={2} mb={3} flexWrap="wrap">
        <TextField
          select
          label="Status Filter"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          sx={{ minWidth: 150 }}
        >
          <MenuItem value="all">All Networks</MenuItem>
          <MenuItem value="trusted">Trusted</MenuItem>
          <MenuItem value="unknown">Unknown</MenuItem>
          <MenuItem value="suspicious">Suspicious</MenuItem>
        </TextField>
        
        <TextField
          label="Search Networks"
          placeholder="Search SSID or BSSID..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          InputProps={{
            startAdornment: <Search sx={{ mr: 1, color: 'text.secondary' }} />
          }}
          sx={{ minWidth: 300 }}
        />

        <Button
          variant={showThreatsOnly ? 'contained' : 'outlined'}
          color="error"
          onClick={() => setShowThreatsOnly(!showThreatsOnly)}
          startIcon={<Warning />}
        >
          {showThreatsOnly ? 'Show All' : 'Threats Only'}
        </Button>
      </Box>

      {/* Networks Table */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Detected Networks ({networks.length})
          </Typography>
          <TableContainer component={Paper} variant="outlined">
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>SSID</TableCell>
                  <TableCell>BSSID</TableCell>
                  <TableCell>Signal</TableCell>
                  <TableCell>Channel</TableCell>
                  <TableCell>Security</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Threat Level</TableCell>
                  <TableCell>Seen Count</TableCell>
                  <TableCell>Last Seen</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {networks
                  .filter(network => !showThreatsOnly || threats.some(t => t.bssid === network.bssid))
                  .map((network) => {
                    const networkThreat = threats.find(t => t.bssid === network.bssid);
                    return (
                      <TableRow key={network._id}>
                        <TableCell>
                          <Typography variant="body2" fontWeight="medium">
                            {network.ssid || 'Hidden Network'}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {network.bssid}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Box display="flex" alignItems="center" gap={1}>
                            {getSignalIcon(network.rssi)}
                            <Typography variant="body2">
                              {network.rssi} dBm
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>{network.channel}</TableCell>
                        <TableCell>
                          <Chip 
                            label={network.encType} 
                            size="small"
                            color={network.encType === 'Open' ? 'error' : 'default'}
                          />
                        </TableCell>
                        <TableCell>
                          {getStatusChip(network.status)}
                        </TableCell>
                        <TableCell>
                          {networkThreat ? (
                            <Chip 
                              label={networkThreat.riskLevel.toUpperCase()} 
                              size="small"
                              color={networkThreat.riskLevel === 'critical' || networkThreat.riskLevel === 'high' ? 'error' : 'warning'}
                            />
                          ) : (
                            <Chip label="SAFE" size="small" color="success" />
                          )}
                        </TableCell>
                        <TableCell>{network.seenCount}</TableCell>
                        <TableCell>
                          <Tooltip title={format(new Date(network.lastSeen), 'PPpp')}>
                            <Typography variant="body2">
                              {formatDistanceToNow(new Date(network.lastSeen), { addSuffix: true })}
                            </Typography>
                          </Tooltip>
                        </TableCell>
                        <TableCell>
                          <Box display="flex" gap={1}>
                            <Button
                              size="small"
                              color="success"
                              onClick={() => updateNetworkStatus(network._id, 'trusted')}
                              disabled={network.status === 'trusted'}
                            >
                              Trust
                            </Button>
                            <Button
                              size="small"
                              color="error"
                              onClick={() => updateNetworkStatus(network._id, 'suspicious')}
                              disabled={network.status === 'suspicious'}
                            >
                              Flag
                            </Button>
                          </Box>
                        </TableCell>
                      </TableRow>
                    );
                  })}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
    </Container>
  );
};

export default Dashboard;
