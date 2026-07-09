import Layout from '../components/Layout';
import Link from 'next/link';

export default function Features() {
  return (
    <Layout title="Features - Squawk DNS" page="features">
      {/* Hero Section */}
      <section className="bg-gradient-primary text-white py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center">
              <div className="mb-3">
                <span className="badge bg-light text-primary fs-6 px-3 py-2">
                  <i className="fas fa-shield-alt me-2"></i>Squawk DNS, a Penguin Technologies Solution
                </span>
              </div>
              <h1 className="display-4 fw-bold mb-4">Enterprise DNS Features</h1>
              <p className="lead">Complete overview of Squawk DNS capabilities - from advanced security to high performance infrastructure designed for enterprise environments.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Enterprise Feature Highlight */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <div className="mb-3">
                <span className="badge bg-primary fs-6 px-3 py-2">
                  <i className="fas fa-crown me-2"></i>Enterprise Edition Exclusive
                </span>
              </div>
              <h2 className="fw-bold">Selective DNS Routing</h2>
              <p className="lead text-muted">One secure DNS endpoint, multiple access levels</p>
            </div>
          </div>
          
          <div className="row align-items-center">
            <div className="col-lg-6">
              <div className="pe-lg-4">
                <h4 className="fw-bold mb-3">Revolutionary DNS Security Architecture</h4>
                <p className="mb-4">
                  The game-changing feature that sets Squawk DNS Enterprise apart: serve different DNS responses 
                  to different users from a single secure endpoint, based on authentication and permissions.
                </p>
                
                <div className="row g-3">
                  <div className="col-md-6">
                    <div className="p-3 bg-success bg-opacity-10 rounded">
                      <h6 className="text-success"><i className="fas fa-users me-2"></i>Internal Users</h6>
                      <p className="mb-0 small">Access private corporate DNS entries + public internet DNS</p>
                    </div>
                  </div>
                  <div className="col-md-6">
                    <div className="p-3 bg-warning bg-opacity-10 rounded">
                      <h6 className="text-warning"><i className="fas fa-globe me-2"></i>External Users</h6>
                      <p className="mb-0 small">Receive only public DNS - private entries stay hidden</p>
                    </div>
                  </div>
                </div>
                
                <div className="mt-4">
                  <Link href="/pricing" className="btn btn-primary btn-lg me-3">
                    <i className="fas fa-crown me-2"></i>Get Enterprise
                  </Link>
                  <a href="mailto:sales@penguincloud.io" className="btn btn-outline-primary btn-lg">
                    <i className="fas fa-envelope me-2"></i>Contact Sales
                  </a>
                </div>
              </div>
            </div>
            
            <div className="col-lg-6">
              <div className="text-center">
                <div className="card bg-dark text-light shadow-lg">
                  <div className="card-header bg-primary">
                    <h6 className="mb-0"><i className="fas fa-server me-2"></i>Single DNS Server - Multiple Security Contexts</h6>
                  </div>
                  <div className="card-body">
                    <div className="row">
                      <div className="col-6">
                        <div className="p-2 bg-success bg-opacity-25 rounded mb-2">
                          <small><strong>Internal User Query</strong></small><br />
                          <code className="text-success">internal.corp.com → 10.0.50.5</code>
                        </div>
                        <div className="p-2 bg-info bg-opacity-25 rounded">
                          <small><strong>Public Query</strong></small><br />
                          <code className="text-info">google.com → 142.250.191.14</code>
                        </div>
                      </div>
                      <div className="col-6">
                        <div className="p-2 bg-danger bg-opacity-25 rounded mb-2">
                          <small><strong>External User Query</strong></small><br />
                          <code className="text-danger">internal.corp.com → NXDOMAIN</code>
                        </div>
                        <div className="p-2 bg-info bg-opacity-25 rounded">
                          <small><strong>Public Query</strong></small><br />
                          <code className="text-info">google.com → 142.250.191.14</code>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Feature Categories Preview */}
      <section className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">Complete Feature Overview</h2>
              <p className="text-muted">Community and Premium features side by side</p>
            </div>
          </div>

          <div className="row g-4">
            {/* Security Features */}
            <div className="col-lg-4 col-md-6">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-danger text-white rounded-circle mx-auto mb-3 d-flex align-items-center justify-content-center" style={{width: '80px', height: '80px'}}>
                    <i className="fas fa-shield-virus fa-2x"></i>
                  </div>
                  <h5 className="card-title">Security & Authentication</h5>
                  <ul className="list-unstyled text-start text-muted small">
                    <li><i className="fas fa-check text-success me-2"></i>mTLS Client Authentication</li>
                    <li><i className="fas fa-check text-success me-2"></i>DNS Blackholing (Maravento)</li>
                    <li><i className="fas fa-check text-success me-2"></i>Brute Force Protection</li>
                    <li><i className="fas fa-check text-success me-2"></i>Comprehensive Security Logging</li>
                    <li><i className="fas fa-check text-success me-2"></i>Token-based Authentication</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Performance Features */}
            <div className="col-lg-4 col-md-6">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-success text-white rounded-circle mx-auto mb-3 d-flex align-items-center justify-content-center" style={{width: '80px', height: '80px'}}>
                    <i className="fas fa-tachometer-alt fa-2x"></i>
                  </div>
                  <h5 className="card-title">High Performance</h5>
                  <ul className="list-unstyled text-start text-muted small">
                    <li><i className="fas fa-check text-success me-2"></i>HTTP/3 Support</li>
                    <li><i className="fas fa-check text-success me-2"></i>Redis/Valkey Caching</li>
                    <li><i className="fas fa-check text-success me-2"></i>Async Processing</li>
                    <li><i className="fas fa-check text-success me-2"></i>~10ms Go Client Cold Start</li>
                    <li><i className="fas fa-check text-success me-2"></i>Minimal Memory Usage (15MB)</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Enterprise Features */}
            <div className="col-lg-4 col-md-6">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-primary text-white rounded-circle mx-auto mb-3 d-flex align-items-center justify-content-center" style={{width: '80px', height: '80px'}}>
                    <i className="fas fa-users-cog fa-2x"></i>
                  </div>
                  <h5 className="card-title">Enterprise Ready</h5>
                  <ul className="list-unstyled text-start text-muted small">
                    <li><i className="fas fa-check text-success me-2"></i>SSO Integration (SAML, LDAP, OAuth2)</li>
                    <li><i className="fas fa-check text-success me-2"></i>Multi-Factor Authentication</li>
                    <li><i className="fas fa-check text-success me-2"></i>Web Management Console</li>
                    <li><i className="fas fa-check text-success me-2"></i>Role-based Access Control</li>
                    <li><i className="fas fa-check text-success me-2"></i>Comprehensive Auditing</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Advanced Analytics & Threat Intelligence */}
            <div className="col-lg-4 col-md-6">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-warning text-white rounded-circle mx-auto mb-3 d-flex align-items-center justify-content-center" style={{width: '80px', height: '80px'}}>
                    <i className="fas fa-brain fa-2x"></i>
                  </div>
                  <h5 className="card-title">Advanced Analytics & Threat Intelligence</h5>
                  <ul className="list-unstyled text-start text-muted small">
                    <li><i className="fas fa-crown text-warning me-1"></i> <i className="fas fa-check text-success me-2"></i>DNS Performance Monitoring with detailed timing analytics</li>
                    <li><i className="fas fa-crown text-warning me-1"></i> <i className="fas fa-check text-success me-2"></i>Real-time WHOIS lookup service</li>
                    <li><i className="fas fa-crown text-warning me-1"></i> <i className="fas fa-check text-success me-2"></i>Multiple IOC threat intelligence feeds</li>
                    <li><i className="fas fa-check text-success me-2"></i>Prometheus metrics export</li>
                    <li><i className="fas fa-check text-success me-2"></i>Comprehensive audit logging</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Performance Monitoring */}
            <div className="col-lg-4 col-md-6">
              <div className="card h-100 border-0 shadow-sm border-warning">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-gradient-primary text-white rounded-circle mx-auto mb-3 d-flex align-items-center justify-content-center" style={{width: '80px', height: '80px'}}>
                    <i className="fas fa-tachometer-alt fa-2x"></i>
                  </div>
                  <div className="badge bg-warning text-dark mb-2">
                    <i className="fas fa-crown me-1"></i>Enterprise Exclusive
                  </div>
                  <h5 className="card-title">DNS Performance Monitoring</h5>
                  <ul className="list-unstyled text-start text-muted small">
                    <li><i className="fas fa-check text-success me-2"></i>Client-side performance statistics</li>
                    <li><i className="fas fa-check text-success me-2"></i>DNS timing breakdown (lookup, TLS, transfer)</li>
                    <li><i className="fas fa-check text-success me-2"></i>Jitter detection and baseline tracking</li>
                    <li><i className="fas fa-check text-success me-2"></i>Automated performance alerts</li>
                    <li><i className="fas fa-check text-success me-2"></i>Centralized performance dashboards</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Management & Configuration */}
            <div className="col-lg-4 col-md-6">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-info text-white rounded-circle mx-auto mb-3 d-flex align-items-center justify-content-center" style={{width: '80px', height: '80px'}}>
                    <i className="fas fa-cogs fa-2x"></i>
                  </div>
                  <h5 className="card-title">Management & Configuration</h5>
                  <ul className="list-unstyled text-start text-muted small">
                    <li><i className="fas fa-crown text-warning me-1"></i> <i className="fas fa-check text-success me-2"></i>Client configuration management</li>
                    <li><i className="fas fa-check text-success me-2"></i>Web-based management console</li>
                    <li><i className="fas fa-check text-success me-2"></i>REST API for automation</li>
                    <li><i className="fas fa-check text-success me-2"></i>Role-based access control</li>
                    <li><i className="fas fa-check text-success me-2"></i>System tray health monitoring</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Deployment Options */}
            <div className="col-lg-4 col-md-6">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-info text-white rounded-circle mx-auto mb-3 d-flex align-items-center justify-content-center" style={{width: '80px', height: '80px'}}>
                    <i className="fas fa-cloud fa-2x"></i>
                  </div>
                  <h5 className="card-title">Flexible Deployment</h5>
                  <ul className="list-unstyled text-start text-muted small">
                    <li><i className="fas fa-check text-success me-2"></i>Docker Container Support</li>
                    <li><i className="fas fa-check text-success me-2"></i>Native Package Installation</li>
                    <li><i className="fas fa-check text-success me-2"></i>Cross-platform Compatibility</li>
                    <li><i className="fas fa-check text-success me-2"></i>Kubernetes Ready</li>
                    <li><i className="fas fa-check text-success me-2"></i>Cloud Provider Integration</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Client Features */}
            <div className="col-lg-4 col-md-6">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-secondary text-white rounded-circle mx-auto mb-3 d-flex align-items-center justify-content-center" style={{width: '80px', height: '80px'}}>
                    <i className="fas fa-desktop fa-2x"></i>
                  </div>
                  <h5 className="card-title">Client Applications</h5>
                  <ul className="list-unstyled text-start text-muted small">
                    <li><i className="fas fa-check text-success me-2"></i>Go Native Client</li>
                    <li><i className="fas fa-check text-success me-2"></i>Python System Tray App</li>
                    <li><i className="fas fa-check text-success me-2"></i>DNS Fallback Support</li>
                    <li><i className="fas fa-check text-success me-2"></i>Multi-server Failover</li>
                    <li><i className="fas fa-check text-success me-2"></i>Captive Portal Detection</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Detailed Security Features */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 mb-5">
              <h2 className="fw-bold text-center mb-4">Advanced Security Architecture</h2>
              <p className="lead text-center text-muted">Enterprise-grade security features designed to protect against modern DNS threats</p>
            </div>
          </div>
          <div className="row g-4">
            <div className="col-lg-6">
              <div className="feature-detail">
                <h4><i className="fas fa-certificate text-primary me-2"></i>Mutual TLS Authentication</h4>
                <p>Advanced client authentication using X.509 certificates. Each client must present a valid certificate signed by your CA, ensuring only authorized devices can access your DNS infrastructure.</p>
                <ul className="list-unstyled">
                  <li><i className="fas fa-check text-success me-2"></i>Certificate-based client identity</li>
                  <li><i className="fas fa-check text-success me-2"></i>CA hierarchy support</li>
                  <li><i className="fas fa-check text-success me-2"></i>Certificate revocation checking</li>
                  <li><i className="fas fa-check text-success me-2"></i>ECC and RSA certificate support</li>
                </ul>
              </div>
            </div>
            <div className="col-lg-6">
              <div className="feature-detail">
                <h4><i className="fas fa-shield-virus text-danger me-2"></i>DNS Security & Filtering</h4>
                <p>Comprehensive DNS security with malware protection, blacklist filtering, and threat intelligence integration to block malicious domains before they can harm your network.</p>
                <ul className="list-unstyled">
                  <li><i className="fas fa-check text-success me-2"></i>Maravento blacklist integration (2M+ domains)</li>
                  <li><i className="fas fa-check text-success me-2"></i>Real-time threat intelligence</li>
                  <li><i className="fas fa-check text-success me-2"></i>Custom domain filtering rules</li>
                  <li><i className="fas fa-check text-success me-2"></i>DNS sinkholing for malicious domains</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Performance & Scalability */}
      <section className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 mb-5">
              <h2 className="fw-bold text-center mb-4">High Performance Infrastructure</h2>
              <p className="lead text-center text-muted">Optimized for speed and scalability with modern protocols and caching</p>
            </div>
          </div>
          <div className="row g-4">
            <div className="col-lg-4">
              <div className="text-center">
                <div className="performance-metric bg-primary text-white rounded p-4 mb-3">
                  <h3 className="display-6 fw-bold">~10ms</h3>
                  <p className="mb-0">Cold Start Time</p>
                </div>
                <h5>Lightning Fast Go Client</h5>
                <p className="text-muted">Native Go implementation with minimal startup overhead and efficient memory usage for instant DNS resolution.</p>
              </div>
            </div>
            <div className="col-lg-4">
              <div className="text-center">
                <div className="performance-metric bg-success text-white rounded p-4 mb-3">
                  <h3 className="display-6 fw-bold">HTTP/3</h3>
                  <p className="mb-0">Protocol Support</p>
                </div>
                <h5>Modern Protocol Stack</h5>
                <p className="text-muted">Full HTTP/3 support with QUIC transport for improved performance over unreliable networks and reduced latency.</p>
              </div>
            </div>
            <div className="col-lg-4">
              <div className="text-center">
                <div className="performance-metric bg-warning text-white rounded p-4 mb-3">
                  <h3 className="display-6 fw-bold">15MB</h3>
                  <p className="mb-0">Memory Usage</p>
                </div>
                <h5>Resource Efficient</h5>
                <p className="text-muted">Minimal resource footprint with intelligent caching and connection pooling for maximum efficiency.</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Enterprise Integration */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 mb-5">
              <h2 className="fw-bold text-center mb-4">Enterprise Integration</h2>
              <p className="lead text-center text-muted">Seamless integration with existing enterprise infrastructure and identity systems</p>
            </div>
          </div>
          <div className="row g-4">
            <div className="col-lg-6">
              <div className="integration-feature p-4 bg-white rounded shadow-sm h-100">
                <h4><i className="fas fa-users-cog text-primary me-2"></i>Identity Management</h4>
                <p>Full integration with enterprise identity providers for centralized user management and single sign-on capabilities.</p>
                <div className="row">
                  <div className="col-md-6">
                    <ul className="list-unstyled">
                      <li><i className="fas fa-check text-success me-2"></i>SAML 2.0</li>
                      <li><i className="fas fa-check text-success me-2"></i>LDAP/Active Directory</li>
                      <li><i className="fas fa-check text-success me-2"></i>OAuth 2.0/OIDC</li>
                    </ul>
                  </div>
                  <div className="col-md-6">
                    <ul className="list-unstyled">
                      <li><i className="fas fa-check text-success me-2"></i>Multi-factor Authentication</li>
                      <li><i className="fas fa-check text-success me-2"></i>Role-based Access Control</li>
                      <li><i className="fas fa-check text-success me-2"></i>Group Policy Integration</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-lg-6">
              <div className="integration-feature p-4 bg-white rounded shadow-sm h-100">
                <h4><i className="fas fa-chart-line text-success me-2"></i>Monitoring & Analytics</h4>
                <p>Comprehensive monitoring capabilities with real-time metrics, alerting, and integration with enterprise monitoring systems.</p>
                <div className="row">
                  <div className="col-md-6">
                    <ul className="list-unstyled">
                      <li><i className="fas fa-crown text-warning me-1"></i> <i className="fas fa-check text-success me-2"></i>DNS Performance Monitoring</li>
                      <li><i className="fas fa-check text-success me-2"></i>Prometheus Metrics</li>
                      <li><i className="fas fa-check text-success me-2"></i>Grafana Dashboards</li>
                      <li><i className="fas fa-check text-success me-2"></i>SNMP Support</li>
                    </ul>
                  </div>
                  <div className="col-md-6">
                    <ul className="list-unstyled">
                      <li><i className="fas fa-crown text-warning me-1"></i> <i className="fas fa-check text-success me-2"></i>WHOIS Lookup Service</li>
                      <li><i className="fas fa-check text-success me-2"></i>Syslog Integration</li>
                      <li><i className="fas fa-check text-success me-2"></i>Health Check APIs</li>
                      <li><i className="fas fa-check text-success me-2"></i>Performance Analytics</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Enterprise Analytics & Intelligence */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 mb-5 text-center">
              <div className="badge bg-warning text-dark fs-6 px-3 py-2 mb-3">
                <i className="fas fa-crown me-2"></i>Enterprise Edition Exclusive
              </div>
              <h2 className="fw-bold mb-4">Advanced Analytics & Intelligence</h2>
              <p className="lead text-muted">Enterprise-exclusive features for comprehensive DNS analytics and threat intelligence</p>
            </div>
          </div>
          
          <div className="row g-4">
            <div className="col-lg-6">
              <div className="feature-deep-dive p-4 bg-white rounded shadow-sm h-100">
                <div className="d-flex align-items-start mb-3">
                  <div className="feature-icon bg-primary text-white rounded p-3 me-3">
                    <i className="fas fa-tachometer-alt fa-2x"></i>
                  </div>
                  <div>
                    <h4 className="fw-bold">DNS Performance Monitoring</h4>
                    <p className="text-muted mb-0">Real-time performance analytics with detailed timing breakdown</p>
                  </div>
                </div>
                <ul className="list-unstyled">
                  <li className="mb-2"><i className="fas fa-stopwatch text-success me-2"></i><strong>DNS Lookup Timing:</strong> Track DNS resolution performance from client perspective</li>
                  <li className="mb-2"><i className="fas fa-handshake text-success me-2"></i><strong>Connection Analysis:</strong> TCP connection and TLS handshake timing metrics</li>
                  <li className="mb-2"><i className="fas fa-chart-bar text-success me-2"></i><strong>Baseline Tracking:</strong> Establish performance baselines and detect anomalies</li>
                  <li className="mb-2"><i className="fas fa-bell text-success me-2"></i><strong>Smart Alerts:</strong> Automated performance threshold monitoring</li>
                </ul>
              </div>
            </div>
            
            <div className="col-lg-6">
              <div className="feature-deep-dive p-4 bg-white rounded shadow-sm h-100">
                <div className="d-flex align-items-start mb-3">
                  <div className="feature-icon bg-info text-white rounded p-3 me-3">
                    <i className="fas fa-search fa-2x"></i>
                  </div>
                  <div>
                    <h4 className="fw-bold">WHOIS Intelligence Service</h4>
                    <p className="text-muted mb-0">Real-time WHOIS lookups with caching and search capabilities</p>
                  </div>
                </div>
                <ul className="list-unstyled">
                  <li className="mb-2"><i className="fas fa-globe text-success me-2"></i><strong>Domain Intelligence:</strong> Instant WHOIS lookups for domains and IP addresses</li>
                  <li className="mb-2"><i className="fas fa-database text-success me-2"></i><strong>Smart Caching:</strong> Cached results with automatic refresh and cleanup</li>
                  <li className="mb-2"><i className="fas fa-search text-success me-2"></i><strong>Advanced Search:</strong> Search by registrar, organization, or nameserver</li>
                  <li className="mb-2"><i className="fas fa-chart-line text-success me-2"></i><strong>Usage Analytics:</strong> Track WHOIS lookup patterns and statistics</li>
                </ul>
              </div>
            </div>
          </div>
          
          <div className="row g-4 mt-2">
            <div className="col-lg-6">
              <div className="feature-deep-dive p-4 bg-white rounded shadow-sm h-100">
                <div className="d-flex align-items-start mb-3">
                  <div className="feature-icon bg-danger text-white rounded p-3 me-3">
                    <i className="fas fa-shield-virus fa-2x"></i>
                  </div>
                  <div>
                    <h4 className="fw-bold">IOC Threat Intelligence</h4>
                    <p className="text-muted mb-0">Multiple threat intelligence feeds with custom overrides</p>
                  </div>
                </div>
                <ul className="list-unstyled">
                  <li className="mb-2"><i className="fas fa-rss text-success me-2"></i><strong>Multiple Feeds:</strong> 5+ default threat intelligence feeds with custom feed support</li>
                  <li className="mb-2"><i className="fas fa-cog text-success me-2"></i><strong>Smart Overrides:</strong> Custom allow/block rules with expiration times</li>
                  <li className="mb-2"><i className="fas fa-sync text-success me-2"></i><strong>Auto Updates:</strong> Automatic feed updates with configurable intervals</li>
                  <li className="mb-2"><i className="fas fa-chart-pie text-success me-2"></i><strong>IOC Analytics:</strong> Comprehensive statistics and blocking reports</li>
                </ul>
              </div>
            </div>
            
            <div className="col-lg-6">
              <div className="feature-deep-dive p-4 bg-white rounded shadow-sm h-100">
                <div className="d-flex align-items-start mb-3">
                  <div className="feature-icon bg-success text-white rounded p-3 me-3">
                    <i className="fas fa-sliders-h fa-2x"></i>
                  </div>
                  <div>
                    <h4 className="fw-bold">Client Configuration Management</h4>
                    <p className="text-muted mb-0">Centralized client configuration with JWT-based deployment</p>
                  </div>
                </div>
                <ul className="list-unstyled">
                  <li className="mb-2"><i className="fas fa-key text-success me-2"></i><strong>JWT Authentication:</strong> Secure domain-based client configuration</li>
                  <li className="mb-2"><i className="fas fa-users text-success me-2"></i><strong>Role Management:</strong> Client-Reader, Client-Maintainer, Domain-Admin roles</li>
                  <li className="mb-2"><i className="fas fa-history text-success me-2"></i><strong>Version Control:</strong> Configuration versioning with rollback capabilities</li>
                  <li className="mb-2"><i className="fas fa-monitor text-success me-2"></i><strong>Client Monitoring:</strong> Track client status and configuration pulls</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Deployment Options */}
      <section className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 mb-5">
              <h2 className="fw-bold text-center mb-4">Flexible Deployment Options</h2>
              <p className="lead text-center text-muted">Deploy anywhere - cloud, on-premises, or hybrid environments</p>
            </div>
          </div>
          <div className="row g-4">
            <div className="col-lg-4">
              <div className="deployment-option text-center p-4 bg-primary text-white rounded">
                <i className="fab fa-docker fa-3x mb-3"></i>
                <h4>Container Deployment</h4>
                <p>Docker containers with Kubernetes support for scalable, orchestrated deployments in any environment.</p>
              </div>
            </div>
            <div className="col-lg-4">
              <div className="deployment-option text-center p-4 bg-success text-white rounded">
                <i className="fas fa-server fa-3x mb-3"></i>
                <h4>Native Installation</h4>
                <p>Native packages for major Linux distributions, Windows, and macOS with system service integration.</p>
              </div>
            </div>
            <div className="col-lg-4">
              <div className="deployment-option text-center p-4 bg-info text-white rounded">
                <i className="fas fa-cloud fa-3x mb-3"></i>
                <h4>Cloud Ready</h4>
                <p>Optimized for AWS, Azure, GCP, and other cloud platforms with auto-scaling and load balancing support.</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Call to Action */}
      <section className="py-5 bg-primary text-white">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center">
              <h3 className="fw-bold mb-4">Ready to Experience These Features?</h3>
              <p className="lead mb-4">Get started with Squawk DNS today and see enterprise-grade DNS security in action.</p>
              <div className="cta-buttons">
                <Link href="/download/" className="btn btn-light btn-lg me-3">
                  <i className="fas fa-download me-2"></i>Download Now
                </Link>
                <Link href="/pricing/" className="btn btn-outline-light btn-lg me-3">
                  <i className="fas fa-dollar-sign me-2"></i>View Pricing
                </Link>
                <Link href="/documentation/" className="btn btn-outline-light btn-lg">
                  <i className="fas fa-book me-2"></i>Documentation
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>
    </Layout>
  );
}