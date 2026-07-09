import Layout from '../components/Layout';
import Link from 'next/link';

export default function Enterprise() {
  return (
    <Layout title="Enterprise Solutions - Squawk DNS" page="enterprise">
      {/* Hero Section */}
      <section className="bg-gradient-primary text-white py-5">
        <div className="container">
          <div className="row align-items-center">
            <div className="col-lg-6">
              <div className="mb-3">
                <span className="badge bg-light text-primary fs-6 px-3 py-2">
                  <i className="fas fa-shield-alt me-2"></i>Squawk DNS, a Penguin Technologies Solution
                </span>
              </div>
              <h1 className="display-4 fw-bold mb-4">Enterprise DNS Security</h1>
              <p className="lead mb-4">
                Secure your enterprise infrastructure with advanced DNS-over-HTTPS, 
                comprehensive authentication, and enterprise-grade security features designed for large organizations.
              </p>
              <div className="d-flex gap-3 flex-wrap">
                <a href="mailto:sales@penguincloud.io" className="btn btn-light btn-lg">
                  <i className="fas fa-envelope me-2"></i>Contact Sales
                </a>
                <Link href="/pricing/" className="btn btn-outline-light btn-lg">
                  <i className="fas fa-dollar-sign me-2"></i>View Pricing
                </Link>
              </div>
            </div>
            <div className="col-lg-6">
              <div className="enterprise-stats bg-white bg-opacity-10 p-4 rounded">
                <div className="row text-center">
                  <div className="col-6 mb-3">
                    <h3 className="text-warning fw-bold">99.9%</h3>
                    <p className="mb-0 small">Uptime SLA</p>
                  </div>
                  <div className="col-6 mb-3">
                    <h3 className="text-warning fw-bold">&lt;10ms</h3>
                    <p className="mb-0 small">Response Time</p>
                  </div>
                  <div className="col-6">
                    <h3 className="text-warning fw-bold">24/7</h3>
                    <p className="mb-0 small">Support</p>
                  </div>
                  <div className="col-6">
                    <h3 className="text-warning fw-bold">2M+</h3>
                    <p className="mb-0 small">Blocked Threats</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Enterprise Features */}
      <section className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">Enterprise-Grade Capabilities</h2>
              <p className="text-muted">Comprehensive DNS security designed for enterprise environments</p>
            </div>
          </div>
          
          <div className="row g-4 mb-5">
            <div className="col-lg-6">
              <div className="feature-card p-4 bg-light rounded h-100">
                <div className="d-flex align-items-start">
                  <div className="feature-icon bg-primary text-white rounded p-3 me-4">
                    <i className="fas fa-certificate fa-2x"></i>
                  </div>
                  <div>
                    <h4>Advanced Authentication</h4>
                    <p className="text-muted mb-3">Multi-layered security with certificate-based authentication and enterprise SSO integration.</p>
                    <ul className="list-unstyled">
                      <li><i className="fas fa-check text-success me-2"></i>Mutual TLS (mTLS) authentication</li>
                      <li><i className="fas fa-check text-success me-2"></i>SAML 2.0 integration</li>
                      <li><i className="fas fa-check text-success me-2"></i>LDAP/Active Directory support</li>
                      <li><i className="fas fa-check text-success me-2"></i>OAuth 2.0/OpenID Connect</li>
                      <li><i className="fas fa-check text-success me-2"></i>Multi-factor authentication</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="col-lg-6">
              <div className="feature-card p-4 bg-light rounded h-100">
                <div className="d-flex align-items-start">
                  <div className="feature-icon bg-success text-white rounded p-3 me-4">
                    <i className="fas fa-shield-virus fa-2x"></i>
                  </div>
                  <div>
                    <h4>Threat Protection</h4>
                    <p className="text-muted mb-3">Comprehensive security with real-time threat intelligence and malware protection.</p>
                    <ul className="list-unstyled">
                      <li><i className="fas fa-check text-success me-2"></i>Maravento blacklist (2M+ domains)</li>
                      <li><i className="fas fa-check text-success me-2"></i>Real-time threat intelligence</li>
                      <li><i className="fas fa-check text-success me-2"></i>Custom filtering rules</li>
                      <li><i className="fas fa-check text-success me-2"></i>DNS sinkholing</li>
                      <li><i className="fas fa-check text-success me-2"></i>Brute force protection</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="row g-4 mb-4">
            <div className="col-lg-6">
              <div className="feature-card p-4 bg-light rounded h-100">
                <div className="d-flex align-items-start">
                  <div className="feature-icon bg-info text-white rounded p-3 me-4">
                    <i className="fas fa-chart-line fa-2x"></i>
                  </div>
                  <div>
                    <h4>Monitoring & Analytics</h4>
                    <p className="text-muted mb-3">Comprehensive monitoring with real-time dashboards and enterprise reporting.</p>
                    <ul className="list-unstyled">
                      <li><i className="fas fa-check text-success me-2"></i>DNS performance monitoring with detailed timing analytics</li>
                      <li><i className="fas fa-check text-success me-2"></i>Real-time performance metrics and response time tracking</li>
                      <li><i className="fas fa-check text-success me-2"></i>Client-side performance statistics and jitter analysis</li>
                      <li><i className="fas fa-check text-success me-2"></i>Grafana dashboard integration with custom visualizations</li>
                      <li><i className="fas fa-check text-success me-2"></i>Prometheus metrics export for infrastructure monitoring</li>
                      <li><i className="fas fa-check text-success me-2"></i>SNMP monitoring support and custom alerting rules</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="col-lg-6">
              <div className="feature-card p-4 bg-light rounded h-100">
                <div className="d-flex align-items-start">
                  <div className="feature-icon bg-warning text-white rounded p-3 me-4">
                    <i className="fas fa-cogs fa-2x"></i>
                  </div>
                  <div>
                    <h4>Management & Control</h4>
                    <p className="text-muted mb-3">Centralized management with role-based access control and comprehensive auditing.</p>
                    <ul className="list-unstyled">
                      <li><i className="fas fa-check text-success me-2"></i>Web-based management console</li>
                      <li><i className="fas fa-check text-success me-2"></i>Role-based access control</li>
                      <li><i className="fas fa-check text-success me-2"></i>Comprehensive audit logging</li>
                      <li><i className="fas fa-check text-success me-2"></i>REST API for automation</li>
                      <li><i className="fas fa-check text-success me-2"></i>Group policy integration</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          {/* DNS Performance Monitoring Feature Highlight */}
          <div className="row">
            <div className="col-lg-12">
              <div className="feature-highlight p-4 bg-gradient-to-r from-blue-50 to-indigo-50 border border-primary rounded">
                <div className="row align-items-center">
                  <div className="col-lg-2 text-center">
                    <div className="feature-icon bg-primary text-white rounded-circle p-4 mx-auto d-inline-block">
                      <i className="fas fa-tachometer-alt fa-3x"></i>
                    </div>
                  </div>
                  <div className="col-lg-10">
                    <h3 className="text-primary fw-bold mb-3">DNS Performance Monitoring</h3>
                    <p className="text-muted mb-3">
                      Advanced DNS-over-HTTPS performance monitoring provides detailed insights into your DNS infrastructure. 
                      Go clients automatically monitor connection performance with randomized testing intervals and comprehensive metrics collection.
                    </p>
                    <div className="row">
                      <div className="col-md-6">
                        <h6 className="fw-bold text-dark">Detailed Performance Metrics:</h6>
                        <ul className="list-unstyled small">
                          <li><i className="fas fa-stopwatch text-success me-2"></i>DNS lookup timing (resolution performance)</li>
                          <li><i className="fas fa-handshake text-success me-2"></i>TCP connection and TLS handshake analysis</li>
                          <li><i className="fas fa-server text-success me-2"></i>Server processing time measurement</li>
                          <li><i className="fas fa-download text-success me-2"></i>Content transfer and response size tracking</li>
                        </ul>
                      </div>
                      <div className="col-md-6">
                        <h6 className="fw-bold text-dark">Smart Monitoring Features:</h6>
                        <ul className="list-unstyled small">
                          <li><i className="fas fa-random text-success me-2"></i>Randomized test intervals (5-10 minutes)</li>
                          <li><i className="fas fa-chart-bar text-success me-2"></i>Baseline performance tracking and jitter detection</li>
                          <li><i className="fas fa-bell text-success me-2"></i>Automatic performance alerts and threshold monitoring</li>
                          <li><i className="fas fa-database text-success me-2"></i>Centralized performance data collection and analysis</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Deployment Options */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">Flexible Deployment Options</h2>
              <p className="text-muted">Deploy Squawk DNS in your preferred environment with full control</p>
            </div>
          </div>
          
          <div className="row g-4">
            <div className="col-lg-4">
              <div className="deployment-card text-center p-4 bg-white rounded shadow-sm h-100">
                <i className="fas fa-cloud fa-3x text-primary mb-3"></i>
                <h4>Cloud Deployment</h4>
                <p className="text-muted">Deploy on AWS, Azure, GCP, or any cloud provider with auto-scaling and load balancing.</p>
                <ul className="list-unstyled text-start">
                  <li><i className="fas fa-check text-success me-2"></i>Multi-region support</li>
                  <li><i className="fas fa-check text-success me-2"></i>Auto-scaling capabilities</li>
                  <li><i className="fas fa-check text-success me-2"></i>Load balancer integration</li>
                  <li><i className="fas fa-check text-success me-2"></i>Cloud monitoring integration</li>
                </ul>
              </div>
            </div>
            
            <div className="col-lg-4">
              <div className="deployment-card text-center p-4 bg-white rounded shadow-sm h-100">
                <i className="fas fa-server fa-3x text-success mb-3"></i>
                <h4>On-Premises</h4>
                <p className="text-muted">Full control with on-premises deployment using containers or native packages.</p>
                <ul className="list-unstyled text-start">
                  <li><i className="fas fa-check text-success me-2"></i>Air-gapped environments</li>
                  <li><i className="fas fa-check text-success me-2"></i>Custom hardware optimization</li>
                  <li><i className="fas fa-check text-success me-2"></i>Integration with existing infrastructure</li>
                  <li><i className="fas fa-check text-success me-2"></i>Compliance and data sovereignty</li>
                </ul>
              </div>
            </div>
            
            <div className="col-lg-4">
              <div className="deployment-card text-center p-4 bg-white rounded shadow-sm h-100">
                <i className="fas fa-network-wired fa-3x text-info mb-3"></i>
                <h4>Hybrid Architecture</h4>
                <p className="text-muted">Combine cloud and on-premises deployment for optimal performance and compliance.</p>
                <ul className="list-unstyled text-start">
                  <li><i className="fas fa-check text-success me-2"></i>Multi-site redundancy</li>
                  <li><i className="fas fa-check text-success me-2"></i>Geographic load distribution</li>
                  <li><i className="fas fa-check text-success me-2"></i>Disaster recovery capabilities</li>
                  <li><i className="fas fa-check text-success me-2"></i>Compliance zone separation</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Support & SLA */}
      <section className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">Enterprise Support & SLA</h2>
              <p className="text-muted">Comprehensive support designed for mission-critical enterprise environments</p>
            </div>
          </div>
          
          <div className="row g-4">
            <div className="col-lg-6">
              <div className="support-feature">
                <h4><i className="fas fa-headset text-primary me-2"></i>24/7 Priority Support</h4>
                <p className="text-muted mb-3">Dedicated support team with guaranteed response times and escalation procedures.</p>
                <ul className="list-unstyled">
                  <li><i className="fas fa-clock text-success me-2"></i>1-hour response for critical issues</li>
                  <li><i className="fas fa-clock text-success me-2"></i>4-hour response for high priority</li>
                  <li><i className="fas fa-clock text-success me-2"></i>24-hour response for standard issues</li>
                  <li><i className="fas fa-phone text-success me-2"></i>Phone and email support</li>
                </ul>
              </div>
            </div>
            
            <div className="col-lg-6">
              <div className="support-feature">
                <h4><i className="fas fa-shield-check text-success me-2"></i>Service Level Agreements</h4>
                <p className="text-muted mb-3">Guaranteed uptime and performance with comprehensive SLA coverage.</p>
                <ul className="list-unstyled">
                  <li><i className="fas fa-percentage text-success me-2"></i>99.9% uptime guarantee</li>
                  <li><i className="fas fa-tachometer-alt text-success me-2"></i>Performance SLA commitments</li>
                  <li><i className="fas fa-file-contract text-success me-2"></i>Financial SLA penalties</li>
                  <li><i className="fas fa-chart-bar text-success me-2"></i>Monthly SLA reporting</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Security & Compliance */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">Security & Compliance</h2>
              <p className="text-muted">Built to meet the highest security standards and compliance requirements</p>
            </div>
          </div>
          
          <div className="row g-4">
            <div className="col-lg-3 col-md-6 text-center">
              <div className="compliance-badge p-4 bg-white rounded shadow-sm h-100">
                <i className="fas fa-certificate fa-3x text-primary mb-3"></i>
                <h5>SOC 2 Ready</h5>
                <p className="text-muted small mb-0">Security controls designed for SOC 2 compliance</p>
              </div>
            </div>
            
            <div className="col-lg-3 col-md-6 text-center">
              <div className="compliance-badge p-4 bg-white rounded shadow-sm h-100">
                <i className="fas fa-lock fa-3x text-success mb-3"></i>
                <h5>GDPR Compliant</h5>
                <p className="text-muted small mb-0">Data protection and privacy controls</p>
              </div>
            </div>
            
            <div className="col-lg-3 col-md-6 text-center">
              <div className="compliance-badge p-4 bg-white rounded shadow-sm h-100">
                <i className="fas fa-shield-virus fa-3x text-warning mb-3"></i>
                <h5>FIPS 140-2</h5>
                <p className="text-muted small mb-0">Cryptographic module standards</p>
              </div>
            </div>
            
            <div className="col-lg-3 col-md-6 text-center">
              <div className="compliance-badge p-4 bg-white rounded shadow-sm h-100">
                <i className="fas fa-file-shield fa-3x text-info mb-3"></i>
                <h5>ISO 27001</h5>
                <p className="text-muted small mb-0">Information security management</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Contact Section */}
      <section className="py-5 bg-primary text-white">
        <div className="container">
          <div className="row text-center">
            <div className="col-lg-12">
              <h3 className="fw-bold mb-4">Ready to Secure Your Enterprise?</h3>
              <p className="lead mb-4">
                Contact our enterprise team to discuss your specific requirements and get a custom deployment plan.
              </p>
              <div className="d-flex gap-3 justify-content-center flex-wrap">
                <a href="mailto:sales@penguincloud.io" className="btn btn-light btn-lg">
                  <i className="fas fa-envelope me-2"></i>Contact Sales Team
                </a>
                <Link href="/pricing/" className="btn btn-outline-light btn-lg">
                  <i className="fas fa-dollar-sign me-2"></i>View Enterprise Pricing
                </Link>
                <Link href="/download/" className="btn btn-outline-light btn-lg">
                  <i className="fas fa-download me-2"></i>Try Community Version
                </Link>
              </div>
              <div className="mt-4">
                <p className="mb-2"><strong>Enterprise Sales:</strong> sales@penguincloud.io</p>
                <p className="mb-0"><small className="opacity-75">Response within 4 hours during business days</small></p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </Layout>
  );
}