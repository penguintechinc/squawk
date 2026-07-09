import Layout from '../components/Layout';
import Link from 'next/link';

export default function Home() {
  return (
    <Layout title="Squawk DNS - Secure DNS-over-HTTPS System" page="home">
      {/* Hero Section */}
      <section className="hero bg-gradient-primary text-white py-5">
        <div className="container">
          <div className="row align-items-center min-vh-75">
            <div className="col-lg-6">
              <div className="hero-content">
                <div className="mb-3">
                  <span className="badge bg-light text-primary fs-6 px-3 py-2">
                    <i className="fas fa-shield-alt me-2"></i>Squawk DNS, a Penguin Technologies Solution
                  </span>
                </div>
                <h1 className="display-4 fw-bold mb-4">
                  Secure DNS-over-HTTPS
                  <span className="text-warning"> with Enterprise Authentication</span>
                </h1>
                <p className="lead mb-4">
                  Squawk DNS provides enterprise-grade DNS-over-HTTPS services with mTLS authentication, 
                  comprehensive security features, and high-performance infrastructure. Perfect for 
                  organizations requiring secure, authenticated DNS resolution.
                </p>
                
                <div className="hero-features mb-4">
                  <div className="row g-3">
                    <div className="col-md-6">
                      <div className="d-flex align-items-center">
                        <i className="fas fa-shield-alt text-success me-2"></i>
                        <span>mTLS Authentication</span>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="d-flex align-items-center">
                        <i className="fas fa-rocket text-warning me-2"></i>
                        <span>High Performance</span>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="d-flex align-items-center">
                        <i className="fas fa-eye-slash text-info me-2"></i>
                        <span>DNS Privacy Protection</span>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="d-flex align-items-center">
                        <i className="fas fa-lock text-danger me-2"></i>
                        <span>Enterprise Security</span>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="hero-actions">
                  <Link href="/download" className="btn btn-light btn-lg me-3">
                    <i className="fas fa-download me-2"></i>
                    Download Free
                  </Link>
                  <Link href="/pricing" className="btn btn-outline-light btn-lg">
                    <i className="fas fa-dollar-sign me-2"></i>
                    View Pricing
                  </Link>
                </div>
              </div>
            </div>
            
            <div className="col-lg-6">
              <div className="hero-demo">
                <div className="card bg-dark text-light shadow-lg">
                  <div className="card-header bg-secondary">
                    <small><i className="fas fa-terminal me-2"></i>Squawk DNS Client</small>
                  </div>
                  <div className="card-body">
                    <pre className="mb-0"><code className="language-bash">{`# Quick Start with Docker
docker run -p 53:53/udp -p 53:53/tcp \\
  -e SQUAWK_SERVER_URL=https://dns.squawkdns.com:8443 \\
  -e SQUAWK_AUTH_TOKEN=your-secure-token \\
  penguincloud/squawk-dns-client:latest forward -v

# Go Client (Enterprise Users)
wget https://github.com/penguincloud/squawk/releases/latest/download/squawk-linux-amd64
chmod +x squawk-linux-amd64
./squawk-linux-amd64 resolve example.com

# Python Client (System Tray)
wget https://github.com/penguincloud/squawk/releases/download/v2.0.0/squawk-dns-client_2.0.0_amd64.deb
sudo dpkg -i squawk-dns-client_2.0.0_amd64.deb`}</code></pre>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Edition Comparison */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">Choose Your Edition</h2>
              <p className="text-muted">Community, Enterprise, or Embedded - all with enterprise-grade security</p>
            </div>
          </div>
          
          <div className="row g-4 mb-5">
            <div className="col-lg-4">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-header bg-success text-white text-center">
                  <h4 className="mb-0"><i className="fab fa-oss me-2"></i>Community Edition</h4>
                  <p className="mb-0 mt-2"><small>Free & Open Source</small></p>
                </div>
                <div className="card-body p-4">
                  <ul className="list-unstyled">
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>Basic DNS-over-HTTPS resolution</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>mTLS authentication support</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>Standard caching with Redis/Valkey</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>Single-token authentication</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>Basic DNS blacklisting</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>Web console interface</li>
                    <li className="mb-2"><i className="fas fa-check text-success me-2"></i>Docker deployment</li>
                  </ul>
                  <div className="text-center mt-4">
                    <Link href="/download" className="btn btn-success btn-lg">
                      <i className="fab fa-github me-2"></i>Download Free
                    </Link>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="col-lg-4">
              <div className="card h-100 border-primary border-3 shadow-lg position-relative">
                <div className="position-absolute top-0 start-50 translate-middle">
                  <span className="badge bg-warning text-dark fs-6 px-3 py-2">Most Popular</span>
                </div>
                <div className="card-header bg-primary text-white text-center">
                  <h4 className="mb-0"><i className="fas fa-crown me-2"></i>Enterprise Edition</h4>
                  <p className="mb-0 mt-2"><small>Licensed with Professional Support</small></p>
                </div>
                <div className="card-body p-4">
                  <div className="mb-3 p-3 bg-primary bg-opacity-10 rounded">
                    <h6 className="text-primary mb-2"><i className="fas fa-star me-2"></i>Key Enterprise Benefit:</h6>
                    <p className="mb-0 fw-bold">
                      <strong>Selective DNS Routing</strong> - One secure endpoint that provides private AND public DNS 
                      entries based on user/group permissions. Internal users get corporate DNS + public internet, 
                      external users get public only.
                    </p>
                  </div>
                  <ul className="list-unstyled">
                    <li className="mb-2"><i className="fas fa-check text-primary me-2"></i><strong>All Community features</strong></li>
                    <li className="mb-2"><i className="fas fa-crown text-primary me-2"></i>Per-user token management</li>
                    <li className="mb-2"><i className="fas fa-crown text-primary me-2"></i>Advanced analytics & reporting</li>
                    <li className="mb-2"><i className="fas fa-crown text-primary me-2"></i>Priority DNS resolution</li>
                    <li className="mb-2"><i className="fas fa-crown text-primary me-2"></i>Enhanced caching optimization</li>
                    <li className="mb-2"><i className="fas fa-crown text-primary me-2"></i>Multi-tenant architecture</li>
                    <li className="mb-2"><i className="fas fa-crown text-primary me-2"></i>Professional technical support</li>
                    <li className="mb-2"><i className="fas fa-crown text-primary me-2"></i>Enterprise SLA</li>
                  </ul>
                  <div className="text-center mt-4">
                    <Link href="/pricing" className="btn btn-primary btn-lg">
                      <i className="fas fa-rocket me-2"></i>Start Enterprise
                    </Link>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="col-lg-4">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-header bg-info text-white text-center">
                  <h4 className="mb-0"><i className="fas fa-microchip me-2"></i>Embedded Edition</h4>
                  <p className="mb-0 mt-2"><small>License for Product Integration</small></p>
                </div>
                <div className="card-body p-4">
                  <div className="mb-3 p-3 bg-info bg-opacity-10 rounded">
                    <h6 className="text-info mb-2"><i className="fas fa-puzzle-piece me-2"></i>Key Embedded Benefits:</h6>
                    <p className="mb-0 fw-bold">
                      <strong>Product Integration</strong> - License Squawk DNS to embed inside your own products, 
                      applications, or hardware solutions. Custom pricing and terms available.
                    </p>
                  </div>
                  <ul className="list-unstyled">
                    <li className="mb-2"><i className="fas fa-check text-info me-2"></i><strong>All Community features</strong></li>
                    <li className="mb-2"><i className="fas fa-puzzle-piece text-info me-2"></i>Embed in your products</li>
                    <li className="mb-2"><i className="fas fa-puzzle-piece text-info me-2"></i>White-label licensing</li>
                    <li className="mb-2"><i className="fas fa-puzzle-piece text-info me-2"></i>Custom branding options</li>
                    <li className="mb-2"><i className="fas fa-puzzle-piece text-info me-2"></i>Redistribution rights</li>
                    <li className="mb-2"><i className="fas fa-puzzle-piece text-info me-2"></i>Volume pricing discounts</li>
                    <li className="mb-2"><i className="fas fa-puzzle-piece text-info me-2"></i>Custom support terms</li>
                    <li className="mb-2"><i className="fas fa-puzzle-piece text-info me-2"></i>Pricing negotiated per use case</li>
                  </ul>
                  <div className="text-center mt-4">
                    <a href="mailto:sales@penguintech.io" className="btn btn-info btn-lg">
                      <i className="fas fa-envelope me-2"></i>Contact Sales
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          <div className="row g-4">
            <div className="col-md-4">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-primary text-white rounded-circle mx-auto mb-3">
                    <i className="fas fa-shield-virus fa-2x"></i>
                  </div>
                  <h5 className="card-title">Advanced Security</h5>
                  <p className="card-text text-muted">
                    mTLS authentication, DNS blackholing with Maravento integration, 
                    brute force protection, and comprehensive security logging.
                  </p>
                </div>
              </div>
            </div>
            
            <div className="col-md-4">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-info text-white rounded-circle mx-auto mb-3">
                    <i className="fas fa-eye-slash fa-2x"></i>
                  </div>
                  <h5 className="card-title">DNS Privacy Protection</h5>
                  <p className="card-text text-muted">
                    Keep your services private - external endpoints accessible by IP 
                    without exposing them in public DNS records. Perfect for internal services.
                  </p>
                </div>
              </div>
            </div>
            
            <div className="col-md-4">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-success text-white rounded-circle mx-auto mb-3">
                    <i className="fas fa-tachometer-alt fa-2x"></i>
                  </div>
                  <h5 className="card-title">High Performance</h5>
                  <p className="card-text text-muted">
                    HTTP/3 support, Redis caching, async processing, and Go client 
                    with ~10ms cold start and minimal memory usage.
                  </p>
                </div>
              </div>
            </div>
          </div>
          
          <div className="row g-4 mt-4">
            <div className="col-md-6">
              <div className="card h-100 border-0 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-warning text-white rounded-circle mx-auto mb-3">
                    <i className="fas fa-users-cog fa-2x"></i>
                  </div>
                  <h5 className="card-title">Enterprise Ready</h5>
                  <p className="card-text text-muted">
                    SSO integration (SAML, LDAP, OAuth2), MFA support, 
                    web console, role-based access, and comprehensive auditing.
                  </p>
                </div>
              </div>
            </div>
            
            <div className="col-md-6">
              <div className="card h-100 border-0 shadow-sm bg-light border-2">
                <div className="card-body text-center p-4">
                  <div className="feature-icon bg-secondary text-white rounded-circle mx-auto mb-3">
                    <i className="fas fa-server fa-2x"></i>
                  </div>
                  <h5 className="card-title">Private Service Discovery</h5>
                  <p className="card-text text-muted">
                    <strong>Revolutionary approach to service privacy:</strong> Your external services 
                    remain accessible by IP address while staying completely invisible in public DNS. 
                    No DNS records = no attack surface for reconnaissance.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Selective DNS Routing Feature */}
      <section className="py-5 bg-gradient-to-r">
        <div className="container">
          <div className="row align-items-center">
            <div className="col-lg-6">
              <div className="pe-lg-5">
                <div className="mb-3">
                  <span className="badge bg-primary fs-6 px-3 py-2">
                    <i className="fas fa-crown me-2"></i>Enterprise Feature
                  </span>
                </div>
                <h2 className="fw-bold mb-4">
                  One Secure DNS Endpoint, 
                  <span className="text-primary"> Multiple Access Levels</span>
                </h2>
                <p className="lead mb-4">
                  The revolutionary selective DNS routing feature allows you to serve different DNS responses 
                  to different users from a single secure endpoint, based on authentication and permissions.
                </p>
                
                <div className="feature-benefits">
                  <div className="row g-3">
                    <div className="col-12">
                      <div className="d-flex align-items-start">
                        <div className="flex-shrink-0">
                          <i className="fas fa-users text-success fs-5 me-3"></i>
                        </div>
                        <div>
                          <h6 className="mb-1">Internal Users</h6>
                          <p className="text-muted mb-0">Get access to private corporate DNS entries + public internet DNS</p>
                        </div>
                      </div>
                    </div>
                    <div className="col-12">
                      <div className="d-flex align-items-start">
                        <div className="flex-shrink-0">
                          <i className="fas fa-globe text-info fs-5 me-3"></i>
                        </div>
                        <div>
                          <h6 className="mb-1">External Users</h6>
                          <p className="text-muted mb-0">Receive only public DNS resolution - private entries remain hidden</p>
                        </div>
                      </div>
                    </div>
                    <div className="col-12">
                      <div className="d-flex align-items-start">
                        <div className="flex-shrink-0">
                          <i className="fas fa-shield-alt text-primary fs-5 me-3"></i>
                        </div>
                        <div>
                          <h6 className="mb-1">Secure Authentication</h6>
                          <p className="text-muted mb-0">Token-based authentication ensures only authorized users access private DNS</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="mt-4">
                  <Link href="/features" className="btn btn-primary btn-lg me-3">
                    <i className="fas fa-info-circle me-2"></i>
                    Learn More
                  </Link>
                  <Link href="/pricing" className="btn btn-outline-primary btn-lg">
                    <i className="fas fa-rocket me-2"></i>
                    Get Enterprise
                  </Link>
                </div>
              </div>
            </div>
            
            <div className="col-lg-6">
              <div className="text-center">
                <div className="position-relative">
                  <div className="card bg-dark text-light shadow-lg mb-3">
                    <div className="card-header bg-success">
                      <small><i className="fas fa-user me-2"></i>Internal User Query</small>
                    </div>
                    <div className="card-body">
                      <pre className="mb-0 text-success"><code>{`nslookup internal.company.com
Server: dns.company.com
Address: 10.0.1.100

internal.company.com resolves to:
10.0.50.5 (Private server accessible)`}</code></pre>
                    </div>
                  </div>
                  
                  <div className="card bg-dark text-light shadow-lg">
                    <div className="card-header bg-warning text-dark">
                      <small><i className="fas fa-globe me-2"></i>External User Query</small>
                    </div>
                    <div className="card-body">
                      <pre className="mb-0 text-warning"><code>{`nslookup internal.company.com
Server: dns.company.com
Address: NXDOMAIN

internal.company.com:
Domain not found (Private entries hidden)`}</code></pre>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Statistics */}
      <section className="py-5 bg-primary text-white">
        <div className="container">
          <div className="row text-center">
            <div className="col-lg-3 col-md-6 mb-4">
              <div className="stat-item">
                <h3 className="display-6 fw-bold text-warning">10ms</h3>
                <p className="mb-0">Go Client Cold Start</p>
              </div>
            </div>
            <div className="col-lg-3 col-md-6 mb-4">
              <div className="stat-item">
                <h3 className="display-6 fw-bold text-warning">1000+</h3>
                <p className="mb-0">Requests per Second</p>
              </div>
            </div>
            <div className="col-lg-3 col-md-6 mb-4">
              <div className="stat-item">
                <h3 className="display-6 fw-bold text-warning">15MB</h3>
                <p className="mb-0">Memory Usage</p>
              </div>
            </div>
            <div className="col-lg-3 col-md-6 mb-4">
              <div className="stat-item">
                <h3 className="display-6 fw-bold text-warning">2M+</h3>
                <p className="mb-0">Blocked Domains</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Call to Action */}
      <section className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center">
              <h2 className="fw-bold mb-4">Ready to Secure Your DNS?</h2>
              <p className="lead text-muted mb-4">
                Get started with Squawk DNS today. Deploy in minutes with Docker or native packages.
              </p>
              
              <div className="cta-buttons">
                <Link href="/download" className="btn btn-primary btn-lg me-3">
                  <i className="fas fa-download me-2"></i>
                  Download Free Version
                </Link>
                <Link href="/pricing" className="btn btn-outline-primary btn-lg me-3">
                  <i className="fas fa-dollar-sign me-2"></i>
                  View Enterprise Plans
                </Link>
                <Link href="/contact" className="btn btn-outline-secondary btn-lg">
                  <i className="fas fa-envelope me-2"></i>
                  Contact Sales
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>
    </Layout>
  );
}