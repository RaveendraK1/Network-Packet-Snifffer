import React, { useState, useEffect, useRef } from 'react';
import './App.css';

function App() {
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [isSniffing, setIsSniffing] = useState(false);
  const [packets, setPackets] = useState([]);
  const [filteredPackets, setFilteredPackets] = useState([]);
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [activeTab, setActiveTab] = useState('packets');
  const [filters, setFilters] = useState({
    protocol: '',
    srcIp: '',
    dstIp: '',
    port: '',
    riskLevel: ''
  });
  const [exporting, setExporting] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  
  const ws = useRef(null);

  // Initialize
  useEffect(() => {
    loadInterfaces();
    connectWebSocket();
    return () => {
      if (ws.current) ws.current.close();
    };
  }, []);

  // WebSocket connection
  const connectWebSocket = () => {
    ws.current = new WebSocket('ws://localhost:8000/ws');
    
    ws.current.onopen = () => {
      console.log('WebSocket connected');
    };
    
    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'alert') {
        setAlerts(prev => [data.alert, ...prev].slice(0, 50));
      } else if (data.type === 'update') {
        loadStats();
      }
    };
    
    ws.current.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
  };

  const loadInterfaces = async () => {
    try {
      const res = await fetch('http://localhost:8000/interfaces');
      const data = await res.json();
      setInterfaces(data.interfaces);
      if (data.interfaces.length > 0) {
        setSelectedInterface(data.interfaces[0].name);
      }
    } catch (error) {
      console.log('Using mock interfaces');
      setInterfaces([
        { name: 'Wi-Fi', status: 'active', ip: '192.168.1.100' },
        { name: 'Ethernet', status: 'inactive', ip: '10.0.0.2' }
      ]);
      setSelectedInterface('Wi-Fi');
    }
  };

  const startSniffing = async () => {
    try {
      const res = await fetch(`http://localhost:8000/start/${selectedInterface}`, {
        method: 'POST'
      });
      const data = await res.json();
      if (data.status === 'started') {
        setIsSniffing(true);
        startDataUpdates();
      }
    } catch (error) {
      alert('Failed to start sniffing. Make sure backend is running.');
    }
  };

  const stopSniffing = async () => {
    try {
      await fetch(`http://localhost:8000/stop/${selectedInterface}`, {
        method: 'POST'
      });
      setIsSniffing(false);
    } catch (error) {
      console.error('Error stopping:', error);
    }
  };

  const startDataUpdates = () => {
    // Load all data initially
    loadPackets();
    loadStats();
    loadAlerts();
    loadSessions();
    
    // Set up intervals for updates
    const intervals = [];
    
    intervals.push(setInterval(loadPackets, 1000));
    intervals.push(setInterval(loadStats, 2000));
    intervals.push(setInterval(loadAlerts, 3000));
    intervals.push(setInterval(loadSessions, 5000));
    
    return () => intervals.forEach(clearInterval);
  };

  const loadPackets = async () => {
    try {
      const res = await fetch(`http://localhost:8000/packets?limit=100&filtered=${Object.keys(filters).some(k => filters[k])}`);
      const data = await res.json();
      setPackets(data.packets || []);
      setFilteredPackets(data.packets || []);
    } catch (error) {
      console.error('Error loading packets:', error);
    }
  };

  const loadStats = async () => {
    try {
      const res = await fetch('http://localhost:8000/stats');
      const data = await res.json();
      setStats(data);
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  };

  const loadAlerts = async () => {
    try {
      const res = await fetch('http://localhost:8000/alerts?limit=20');
      const data = await res.json();
      setAlerts(data.alerts || []);
    } catch (error) {
      console.error('Error loading alerts:', error);
    }
  };

  const loadSessions = async () => {
    try {
      const res = await fetch('http://localhost:8000/sessions');
      const data = await res.json();
      setSessions(data.sessions || []);
    } catch (error) {
      console.error('Error loading sessions:', error);
    }
  };

  const applyFilters = async () => {
    const params = new URLSearchParams();
    if (filters.protocol) params.append('protocols', filters.protocol);
    if (filters.srcIp) params.append('src_ip', filters.srcIp);
    if (filters.dstIp) params.append('dst_ip', filters.dstIp);
    if (filters.port) params.append('port', filters.port);
    if (filters.riskLevel) params.append('risk_level', filters.riskLevel);
    
    try {
      const res = await fetch(`http://localhost:8000/filter?${params}`, {
        method: 'POST'
      });
      await res.json();
      loadPackets();
    } catch (error) {
      console.error('Error applying filters:', error);
    }
  };

  const clearFilters = () => {
    setFilters({
      protocol: '',
      srcIp: '',
      dstIp: '',
      port: '',
      riskLevel: ''
    });
    loadPackets();
  };

  const exportCSV = async () => {
    setExporting(true);
    try {
      const res = await fetch('http://localhost:8000/export/csv');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `packets_${new Date().toISOString().slice(0, 19).replace(/[:]/g, '-')}.csv`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Export error:', error);
    } finally {
      setExporting(false);
    }
  };

  const exportJSON = async () => {
    setExporting(true);
    try {
      const res = await fetch('http://localhost:8000/export/json');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `packets_${new Date().toISOString().slice(0, 19).replace(/[:]/g, '-')}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Export error:', error);
    } finally {
      setExporting(false);
    }
  };

  const analyzePacket = async (packetId) => {
    try {
      const res = await fetch(`http://localhost:8000/analyze/${packetId}`);
      const data = await res.json();
      setAnalysis(data);
      setActiveTab('analysis');
    } catch (error) {
      console.error('Analysis error:', error);
    }
  };

  const getProtocolColor = (protocol) => {
    const colors = {
      'TCP': '#3498db',
      'UDP': '#2ecc71',
      'ICMP': '#e74c3c',
      'HTTP': '#f39c12',
      'HTTPS': '#9b59b6',
      'DNS': '#1abc9c',
      'SSH': '#34495e',
      'FTP': '#16a085',
      'SMTP': '#8e44ad',
      'ARP': '#d35400'
    };
    return colors[protocol] || '#7f8c8d';
  };

  const getRiskColor = (risk) => {
    return risk === 'HIGH' ? '#e74c3c' : risk === 'MEDIUM' ? '#f39c12' : '#2ecc71';
  };

  const getSeverityColor = (severity) => {
    return severity === 'HIGH' ? '#e74c3c' : '#f39c12';
  };

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-left">
          <h1>🚀 ADVANCED PACKET SNIFFER</h1>
          <p className="subtitle">Real-time Network Traffic Analysis & Security Monitoring</p>
        </div>
        <div className="header-right">
          <div className="status-indicator">
            <div className={`status-dot ${isSniffing ? 'active' : 'inactive'}`}></div>
            <span className="status-text">{isSniffing ? 'LIVE CAPTURE' : 'STOPPED'}</span>
          </div>
          {stats && (
            <div className="quick-stats">
              <span>📦 {stats.total_packets || 0}</span>
              <span>⚠️ {stats.alerts || 0}</span>
              <span>🔗 {stats.sessions || 0}</span>
            </div>
          )}
        </div>
      </header>

      {/* Main Container */}
      <div className="main-container">
        {/* Sidebar */}
        <aside className="sidebar">
          <div className="interface-selector">
            <h3>🌐 Network Interface</h3>
            <select 
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={isSniffing}
              className="interface-dropdown"
            >
              {interfaces.map((iface) => (
                <option key={iface.name} value={iface.name}>
                  {iface.name} ({iface.ip}) - {iface.status}
                </option>
              ))}
            </select>
          </div>

          <div className="control-buttons">
            <button 
              className={`btn start-btn ${isSniffing ? 'disabled' : ''}`}
              onClick={startSniffing}
              disabled={isSniffing}
            >
              ▶ START SNIFFING
            </button>
            <button 
              className={`btn stop-btn ${!isSniffing ? 'disabled' : ''}`}
              onClick={stopSniffing}
              disabled={!isSniffing}
            >
              ⏹ STOP
            </button>
          </div>

          <div className="filter-section">
            <h3>🔍 Filters</h3>
            <div className="filter-group">
              <input 
                type="text" 
                placeholder="Source IP" 
                value={filters.srcIp}
                onChange={(e) => setFilters({...filters, srcIp: e.target.value})}
              />
              <input 
                type="text" 
                placeholder="Destination IP" 
                value={filters.dstIp}
                onChange={(e) => setFilters({...filters, dstIp: e.target.value})}
              />
              <input 
                type="text" 
                placeholder="Port" 
                value={filters.port}
                onChange={(e) => setFilters({...filters, port: e.target.value})}
              />
              <select 
                value={filters.protocol}
                onChange={(e) => setFilters({...filters, protocol: e.target.value})}
              >
                <option value="">All Protocols</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="HTTP">HTTP</option>
                <option value="HTTPS">HTTPS</option>
                <option value="DNS">DNS</option>
              </select>
              <select 
                value={filters.riskLevel}
                onChange={(e) => setFilters({...filters, riskLevel: e.target.value})}
              >
                <option value="">All Risks</option>
                <option value="LOW">Low Risk</option>
                <option value="MEDIUM">Medium Risk</option>
                <option value="HIGH">High Risk</option>
              </select>
              <div className="filter-actions">
                <button className="btn apply-btn" onClick={applyFilters}>Apply</button>
                <button className="btn clear-btn" onClick={clearFilters}>Clear</button>
              </div>
            </div>
          </div>

          <div className="export-section">
            <h3>📤 Export</h3>
            <button className="btn export-btn" onClick={exportCSV} disabled={exporting}>
              {exporting ? 'Exporting...' : 'Export CSV'}
            </button>
            <button className="btn export-btn" onClick={exportJSON} disabled={exporting}>
              {exporting ? 'Exporting...' : 'Export JSON'}
            </button>
          </div>
        </aside>

        {/* Main Content */}
        <main className="content">
          {/* Tabs */}
          <div className="tabs">
            <button 
              className={`tab ${activeTab === 'packets' ? 'active' : ''}`}
              onClick={() => setActiveTab('packets')}
            >
              📦 Packets ({filteredPackets.length})
            </button>
            <button 
              className={`tab ${activeTab === 'alerts' ? 'active' : ''}`}
              onClick={() => setActiveTab('alerts')}
            >
              ⚠️ Alerts ({alerts.length})
            </button>
            <button 
              className={`tab ${activeTab === 'sessions' ? 'active' : ''}`}
              onClick={() => setActiveTab('sessions')}
            >
              🔗 Sessions ({sessions.length})
            </button>
            <button 
              className={`tab ${activeTab === 'stats' ? 'active' : ''}`}
              onClick={() => setActiveTab('stats')}
            >
              📊 Statistics
            </button>
            {analysis && (
              <button 
                className={`tab ${activeTab === 'analysis' ? 'active' : ''}`}
                onClick={() => setActiveTab('analysis')}
              >
                🔍 Analysis
              </button>
            )}
          </div>

          {/* Tab Content */}
          <div className="tab-content">
            {activeTab === 'packets' && (
              <div className="packet-table-container">
                <div className="table-header">
                  <h3>Captured Packets</h3>
                  <span>Showing {filteredPackets.length} packets</span>
                </div>
                <div className="table-wrapper">
                  <table className="packet-table">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Time</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Protocol</th>
                        <th>Size</th>
                        <th>Risk</th>
                        <th>Info</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredPackets.length === 0 ? (
                        <tr>
                          <td colSpan="9" className="no-data">
                            {isSniffing ? 'Capturing packets...' : 'No packets captured'}
                          </td>
                        </tr>
                      ) : (
                        filteredPackets.map((packet) => (
                          <tr key={packet.id}>
                            <td>{packet.id}</td>
                            <td>{new Date(packet.timestamp).toLocaleTimeString()}</td>
                            <td className="ip-cell">
                              {packet.src_ip}
                              {packet.src_port && <span className="port">:{packet.src_port}</span>}
                            </td>
                            <td className="ip-cell">
                              {packet.dst_ip}
                              {packet.dst_port && <span className="port">:{packet.dst_port}</span>}
                            </td>
                            <td>
                              <span 
                                className="protocol-badge"
                                style={{ backgroundColor: getProtocolColor(packet.protocol) }}
                              >
                                {packet.protocol}
                              </span>
                            </td>
                            <td>{packet.length} bytes</td>
                            <td>
                              <span 
                                className="risk-badge"
                                style={{ backgroundColor: getRiskColor(packet.risk_level) }}
                              >
                                {packet.risk_level}
                              </span>
                            </td>
                            <td className="summary">{packet.summary}</td>
                            <td>
                              <button 
                                className="action-btn analyze-btn"
                                onClick={() => analyzePacket(packet.id)}
                                title="Analyze"
                              >
                                🔍
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {activeTab === 'alerts' && (
              <div className="alerts-container">
                <div className="alerts-header">
                  <h3>Security Alerts</h3>
                  <span className="alert-count">{alerts.length} alerts</span>
                </div>
                <div className="alerts-list">
                  {alerts.length === 0 ? (
                    <div className="no-alerts">No alerts detected</div>
                  ) : (
                    alerts.map((alert) => (
                      <div key={alert.id} className="alert-item" style={{ borderLeftColor: getSeverityColor(alert.severity) }}>
                        <div className="alert-header">
                          <span className="alert-type" style={{ color: getSeverityColor(alert.severity) }}>
                            {alert.type}
                          </span>
                          <span className="alert-time">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <div className="alert-message">{alert.message}</div>
                        <div className="alert-severity">Severity: {alert.severity}</div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {activeTab === 'sessions' && (
              <div className="sessions-container">
                <div className="sessions-header">
                  <h3>Network Sessions</h3>
                  <span>{sessions.length} active sessions</span>
                </div>
                <div className="sessions-grid">
                  {sessions.map((session) => (
                    <div key={session.id} className="session-card">
                      <div className="session-header">
                        <span className="session-id">{session.id.substring(0, 30)}...</span>
                        <span className="session-packets">{session.packet_count} packets</span>
                      </div>
                      <div className="session-details">
                        <div className="session-route">
                          <span className="source">{session.src_ip}</span>
                          <span className="arrow">→</span>
                          <span className="dest">{session.dst_ip}</span>
                        </div>
                        <div className="session-info">
                          <span className="protocol">{session.protocol}</span>
                          <span className="last-active">Last: {new Date(session.last_active).toLocaleTimeString()}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'stats' && stats && (
              <div className="stats-container">
                <div className="stats-overview">
                  <div className="stat-card large">
                    <div className="stat-value">{stats.total_packets || 0}</div>
                    <div className="stat-label">Total Packets</div>
                  </div>
                  <div className="stat-card large">
                    <div className="stat-value">{stats.bandwidth_mbps ? stats.bandwidth_mbps.toFixed(2) : '0.00'}</div>
                    <div className="stat-label">Bandwidth (Mbps)</div>
                  </div>
                  <div className="stat-card large">
                    <div className="stat-value">{stats.alerts || 0}</div>
                    <div className="stat-label">Security Alerts</div>
                  </div>
                  <div className="stat-card large">
                    <div className="stat-value">{stats.sessions || 0}</div>
                    <div className="stat-label">Active Sessions</div>
                  </div>
                </div>

                <div className="charts-container">
                  <div className="chart-card">
                    <h4>Protocol Distribution</h4>
                    <div className="protocol-chart">
                      {stats.protocol_distribution && Object.entries(stats.protocol_distribution).map(([proto, count]) => (
                        <div key={proto} className="protocol-bar">
                          <div className="bar-label">{proto}</div>
                          <div className="bar-container">
                            <div 
                              className="bar-fill"
                              style={{ 
                                width: `${(count / stats.total_packets) * 100}%`,
                                backgroundColor: getProtocolColor(proto)
                              }}
                            ></div>
                          </div>
                          <div className="bar-value">{count}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="chart-card">
                    <h4>Top Talkers</h4>
                    <div className="talkers-list">
                      {stats.top_talkers && Object.entries(stats.top_talkers).map(([ip, count]) => (
                        <div key={ip} className="talker-item">
                          <span className="talker-ip">{ip}</span>
                          <div className="talker-bar">
                            <div 
                              className="talker-fill"
                              style={{ width: `${(count / stats.total_packets) * 100}%` }}
                            ></div>
                          </div>
                          <span className="talker-count">{count}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'analysis' && analysis && (
              <div className="analysis-container">
                <div className="analysis-header">
                  <h3>Packet Analysis</h3>
                  <button className="btn back-btn" onClick={() => setActiveTab('packets')}>← Back</button>
                </div>
                <div className="analysis-content">
                  <div className="packet-details">
                    <h4>Packet Details</h4>
                    <div className="details-grid">
                      <div className="detail-item">
                        <span className="detail-label">ID:</span>
                        <span className="detail-value">{analysis.packet.id}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">Timestamp:</span>
                        <span className="detail-value">{new Date(analysis.packet.timestamp).toLocaleString()}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">Source:</span>
                        <span className="detail-value">{analysis.packet.src_ip}:{analysis.packet.src_port}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">Destination:</span>
                        <span className="detail-value">{analysis.packet.dst_ip}:{analysis.packet.dst_port}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">Protocol:</span>
                        <span className="detail-value">{analysis.packet.protocol}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">Size:</span>
                        <span className="detail-value">{analysis.packet.length} bytes</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">Risk Level:</span>
                        <span className="detail-value" style={{ color: getRiskColor(analysis.packet.risk_level) }}>
                          {analysis.packet.risk_level}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="analysis-results">
                    <h4>Analysis Results</h4>
                    <div className="analysis-grid">
                      {Object.entries(analysis.analysis).map(([key, value]) => (
                        <div key={key} className="analysis-item">
                          <span className="analysis-label">{key.replace('_', ' ').toUpperCase()}:</span>
                          <span className={`analysis-value ${value ? 'true' : 'false'}`}>
                            {value ? '✓ YES' : '✗ NO'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {analysis.recommendations.length > 0 && (
                    <div className="recommendations">
                      <h4>Recommendations</h4>
                      <ul>
                        {analysis.recommendations.map((rec, idx) => (
                          <li key={idx}>{rec}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </main>
      </div>

      {/* Footer */}
      <footer className="footer">
        <div className="footer-content">
          <p>Advanced Network Packet Sniffer v2.0 | Educational & Security Research Tool</p>
          <div className="footer-stats">
            {stats && (
              <>
                <span>Duration: {stats.duration_seconds ? Math.floor(stats.duration_seconds) : 0}s</span>
                <span>Packets/sec: {stats.duration_seconds ? Math.floor(stats.total_packets / stats.duration_seconds) : 0}</span>
                <span>Status: {isSniffing ? '🟢 LIVE' : '🔴 STOPPED'}</span>
              </>
            )}
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;