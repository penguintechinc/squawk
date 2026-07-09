import Layout from '../components/Layout';
import Link from 'next/link';

export default function Download() {
  return (
    <Layout title="Download - Squawk DNS" page="download">
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
              <h1 className="display-4 fw-bold mb-4">Download Squawk DNS</h1>
              <p className="lead">Get started with Squawk DNS today. Choose from Docker containers, native packages, or build from source.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Quick Start Options */}
      <section className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">Quick Start Options</h2>
              <p className="text-muted">Choose the deployment method that works best for your environment</p>
            </div>
          </div>
          
          <div className="row g-4">
            {/* Docker Option */}
            <div className="col-lg-4">
              <div className="card h-100 border-0 shadow-lg">
                <div className="card-body text-center p-5">
                  <i className="fab fa-docker fa-4x text-primary mb-4"></i>
                  <h3 className="card-title">Docker Container</h3>
                  <p className="text-muted mb-4">The fastest way to get started. Run Squawk DNS in minutes with Docker.</p>
                  <div className="mb-4">
                    <span className="badge bg-success px-3 py-2">Recommended</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Native Packages */}
            <div className="col-lg-4">
              <div className="card h-100 border-0 shadow-lg">
                <div className="card-body text-center p-5">
                  <i className="fas fa-box fa-4x text-success mb-4"></i>
                  <h3 className="card-title">Native Packages</h3>
                  <p className="text-muted mb-4">System packages for Linux distributions with service integration.</p>
                  <div className="mb-4">
                    <span className="badge bg-info px-3 py-2">Production Ready</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Source Code */}
            <div className="col-lg-4">
              <div className="card h-100 border-0 shadow-lg">
                <div className="card-body text-center p-5">
                  <i className="fas fa-code fa-4x text-warning mb-4"></i>
                  <h3 className="card-title">Source Code</h3>
                  <p className="text-muted mb-4">Build from source for custom modifications and development.</p>
                  <div className="mb-4">
                    <span className="badge bg-warning text-dark px-3 py-2">Advanced</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Docker Installation */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 mb-5">
              <div className="d-flex align-items-center mb-4">
                <i className="fab fa-docker fa-3x text-primary me-3"></i>
                <div>
                  <h2 className="fw-bold mb-1">Docker Installation</h2>
                  <p className="text-muted mb-0">Quick deployment using Docker containers</p>
                </div>
              </div>
            </div>
          </div>
          
          <div className="row g-4">
            <div className="col-lg-6">
              <div className="docker-option p-4 bg-white rounded shadow-sm h-100">
                <h4><i className="fas fa-server text-primary me-2"></i>DNS Server</h4>
                <p className="text-muted">Run the Squawk DNS server to provide DNS-over-HTTPS services.</p>
                <div className="code-block bg-dark text-light p-3 rounded mb-3">
                  <code>
                    docker run -d \<br/>
                    &nbsp;&nbsp;-p 8080:8080 \<br/>
                    &nbsp;&nbsp;-e PORT=8080 \<br/>
                    &nbsp;&nbsp;-e AUTH_TOKEN=your-secure-token \<br/>
                    &nbsp;&nbsp;penguincloud/squawk-dns-server:latest
                  </code>
                </div>
                <p className="small text-muted">
                  <i className="fas fa-info-circle me-1"></i>
                  Replace <code>your-secure-token</code> with a secure authentication token.
                </p>
              </div>
            </div>
            
            <div className="col-lg-6">
              <div className="docker-option p-4 bg-white rounded shadow-sm h-100">
                <h4><i className="fas fa-desktop text-success me-2"></i>DNS Client</h4>
                <p className="text-muted">Forward local DNS requests to your Squawk DNS server.</p>
                <div className="code-block bg-dark text-light p-3 rounded mb-3">
                  <code>
                    docker run -d \<br/>
                    &nbsp;&nbsp;-p 53:53/udp -p 53:53/tcp \<br/>
                    &nbsp;&nbsp;-e SQUAWK_SERVER_URL=https://dns.yourdomain.com:8443 \<br/>
                    &nbsp;&nbsp;-e SQUAWK_AUTH_TOKEN=your-secure-token \<br/>
                    &nbsp;&nbsp;penguincloud/squawk-dns-client:latest forward -v
                  </code>
                </div>
                <p className="small text-muted">
                  <i className="fas fa-info-circle me-1"></i>
                  Update the server URL to point to your Squawk DNS server.
                </p>
              </div>
            </div>
          </div>
          
          <div className="row mt-4">
            <div className="col-lg-12 text-center">
              <a href="https://hub.docker.com/r/penguincloud/squawk-dns-server" target="_blank" rel="noopener noreferrer" className="btn btn-primary me-3">
                <i className="fab fa-docker me-2"></i>View on Docker Hub
              </a>
              <Link href="/documentation/" className="btn btn-outline-primary">
                <i className="fas fa-book me-2"></i>Docker Documentation
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Native Packages */}
      <section className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 mb-5">
              <div className="d-flex align-items-center mb-4">
                <i className="fas fa-box fa-3x text-success me-3"></i>
                <div>
                  <h2 className="fw-bold mb-1">Native Packages</h2>
                  <p className="text-muted mb-0">Platform-specific packages with system service integration</p>
                </div>
              </div>
            </div>
          </div>
          
          <div className="row g-4">
            <div className="col-lg-6">
              <div className="package-group p-4 bg-light rounded">
                <h4><i className="fab fa-linux text-warning me-2"></i>Linux Packages</h4>
                <div className="mb-3">
                  <h6>Debian/Ubuntu (.deb)</h6>
                  <div className="code-block bg-dark text-light p-2 rounded mb-2">
                    <code className="small">
                      wget https://github.com/penguincloud/squawk/releases/download/v1.1.1-client/squawk-dns-client_1.1.1_amd64.deb<br/>
                      sudo dpkg -i squawk-dns-client_1.1.1_amd64.deb
                    </code>
                  </div>
                </div>
                
                <div className="mb-3">
                  <h6>Red Hat/CentOS (.rpm)</h6>
                  <div className="code-block bg-dark text-light p-2 rounded mb-2">
                    <code className="small">
                      wget https://github.com/penguincloud/squawk/releases/download/v1.1.1-client/squawk-dns-client-1.1.1-1.x86_64.rpm<br/>
                      sudo rpm -i squawk-dns-client-1.1.1-1.x86_64.rpm
                    </code>
                  </div>
                </div>
                
                <div>
                  <h6>Service Management</h6>
                  <div className="code-block bg-dark text-light p-2 rounded">
                    <code className="small">
                      sudo systemctl enable --now squawk-dns-client<br/>
                      sudo systemctl status squawk-dns-client
                    </code>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="col-lg-6">
              <div className="package-group p-4 bg-light rounded">
                <h4><i className="fab fa-windows text-info me-2"></i>Windows & macOS</h4>
                <div className="mb-3">
                  <h6>Windows (MSI Installer)</h6>
                  <p className="text-muted small">Coming soon - Windows installer with service integration.</p>
                  <a href="mailto:sales@penguincloud.io" className="btn btn-outline-info btn-sm">
                    Request Early Access
                  </a>
                </div>
                
                <div className="mb-3">
                  <h6>macOS (Homebrew)</h6>
                  <p className="text-muted small">Coming soon - macOS package with launchd integration.</p>
                  <a href="mailto:sales@penguincloud.io" className="btn btn-outline-info btn-sm">
                    Request Early Access
                  </a>
                </div>
                
                <div>
                  <h6>Go Binary</h6>
                  <p className="text-muted small">Pre-compiled binaries available for all platforms.</p>
                  <a href="https://github.com/penguincloud/squawk/releases/latest" target="_blank" rel="noopener noreferrer" className="btn btn-success btn-sm">
                    Download Binaries
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Source Code */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 mb-5">
              <div className="d-flex align-items-center mb-4">
                <i className="fas fa-code fa-3x text-warning me-3"></i>
                <div>
                  <h2 className="fw-bold mb-1">Build from Source</h2>
                  <p className="text-muted mb-0">Clone, build, and customize Squawk DNS for your needs</p>
                </div>
              </div>
            </div>
          </div>
          
          <div className="row g-4">
            <div className="col-lg-8">
              <div className="source-instructions p-4 bg-white rounded shadow-sm">
                <h4>Prerequisites</h4>
                <ul className="mb-4">
                  <li>Go 1.21 or later</li>
                  <li>Git</li>
                  <li>Make (optional, for build scripts)</li>
                </ul>
                
                <h4>Build Instructions</h4>
                <div className="code-block bg-dark text-light p-3 rounded mb-3">
                  <code>
                    # Clone the repository<br/>
                    git clone https://github.com/penguincloud/squawk.git<br/>
                    cd squawk<br/><br/>
                    
                    # Build the server<br/>
                    go build -o squawk-dns-server ./cmd/server<br/><br/>
                    
                    # Build the client<br/>
                    go build -o squawk-dns-client ./cmd/client<br/><br/>
                    
                    # Or use the Makefile<br/>
                    make build
                  </code>
                </div>
                
                <h4>Development</h4>
                <div className="code-block bg-dark text-light p-3 rounded">
                  <code>
                    # Run tests<br/>
                    go test ./...<br/><br/>
                    
                    # Run with hot reload<br/>
                    go run ./cmd/server --config config.yaml
                  </code>
                </div>
              </div>
            </div>
            
            <div className="col-lg-4">
              <div className="source-links p-4 bg-white rounded shadow-sm h-100">
                <h4>Source Code Links</h4>
                <div className="d-grid gap-2">
                  <a href="https://github.com/penguincloud/squawk" target="_blank" rel="noopener noreferrer" className="btn btn-outline-dark">
                    <i className="fab fa-github me-2"></i>GitHub Repository
                  </a>
                  <a href="https://github.com/penguincloud/squawk/releases" target="_blank" rel="noopener noreferrer" className="btn btn-outline-success">
                    <i className="fas fa-tag me-2"></i>Latest Release
                  </a>
                  <a href="https://github.com/penguincloud/squawk/issues" target="_blank" rel="noopener noreferrer" className="btn btn-outline-warning">
                    <i className="fas fa-bug me-2"></i>Report Issues
                  </a>
                  <Link href="/documentation/" className="btn btn-outline-primary">
                    <i className="fas fa-book me-2"></i>Dev Documentation
                  </Link>
                </div>
                
                <div className="mt-4">
                  <h6>License</h6>
                  <p className="small text-muted">
                    Squawk DNS is released under the 
                    <a href="https://github.com/penguincloud/squawk/blob/main/LICENSE.md" target="_blank" rel="noopener noreferrer"> AGPL v3 License</a>.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* System Requirements */}
      <section className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">System Requirements</h2>
              <p className="text-muted">Minimal requirements for running Squawk DNS</p>
            </div>
          </div>
          
          <div className="row g-4">
            <div className="col-lg-6">
              <div className="requirements-card p-4 bg-light rounded">
                <h4><i className="fas fa-server text-primary me-2"></i>DNS Server</h4>
                <div className="row">
                  <div className="col-md-6">
                    <ul className="list-unstyled">
                      <li><strong>CPU:</strong> 1 core minimum</li>
                      <li><strong>RAM:</strong> 512MB minimum</li>
                      <li><strong>Storage:</strong> 100MB available</li>
                      <li><strong>Network:</strong> 1 Mbps bandwidth</li>
                    </ul>
                  </div>
                  <div className="col-md-6">
                    <ul className="list-unstyled">
                      <li><strong>OS:</strong> Linux, Windows, macOS</li>
                      <li><strong>Ports:</strong> 8080 (configurable)</li>
                      <li><strong>SSL:</strong> TLS certificate required</li>
                      <li><strong>Optional:</strong> Redis for caching</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="col-lg-6">
              <div className="requirements-card p-4 bg-light rounded">
                <h4><i className="fas fa-desktop text-success me-2"></i>DNS Client</h4>
                <div className="row">
                  <div className="col-md-6">
                    <ul className="list-unstyled">
                      <li><strong>CPU:</strong> Minimal usage</li>
                      <li><strong>RAM:</strong> 15MB typical usage</li>
                      <li><strong>Storage:</strong> 10MB binary size</li>
                      <li><strong>Network:</strong> Internet connectivity</li>
                    </ul>
                  </div>
                  <div className="col-md-6">
                    <ul className="list-unstyled">
                      <li><strong>OS:</strong> Linux, Windows, macOS</li>
                      <li><strong>Ports:</strong> 53 (DNS)</li>
                      <li><strong>Privileges:</strong> Root/Admin for port 53</li>
                      <li><strong>Startup:</strong> ~10ms cold start</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Support Section */}
      <section className="py-5 bg-primary text-white">
        <div className="container">
          <div className="row text-center">
            <div className="col-lg-12">
              <h3 className="fw-bold mb-4">Need Help Getting Started?</h3>
              <p className="lead mb-4">
                Our team is ready to help you deploy Squawk DNS successfully in your environment.
              </p>
              <div className="d-flex gap-3 justify-content-center flex-wrap">
                <Link href="/documentation/" className="btn btn-light btn-lg">
                  <i className="fas fa-book me-2"></i>View Documentation
                </Link>
                <a href="https://github.com/penguincloud/squawk/issues" target="_blank" rel="noopener noreferrer" className="btn btn-outline-light btn-lg">
                  <i className="fab fa-github me-2"></i>Community Support
                </a>
                <a href="mailto:sales@penguincloud.io" className="btn btn-outline-light btn-lg">
                  <i className="fas fa-envelope me-2"></i>Enterprise Support
                </a>
              </div>
            </div>
          </div>
        </div>
      </section>
    </Layout>
  );
}