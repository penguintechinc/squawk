import Layout from '../components/Layout';
import Link from 'next/link';

export default function Documentation() {
  return (
    <Layout title="Documentation - Squawk DNS" page="documentation">
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
              <h1 className="display-4 fw-bold mb-4">Documentation</h1>
              <p className="lead">
                Comprehensive guides, API references, and tutorials to help you deploy and manage Squawk DNS successfully.
              </p>
              <div className="mt-4">
                <a href="https://docs.squawkdns.com" target="_blank" rel="noopener noreferrer" className="btn btn-light btn-lg me-3">
                  <i className="fas fa-external-link-alt me-2"></i>View Full Documentation
                </a>
                <Link href="/download/" className="btn btn-outline-light btn-lg">
                  <i className="fas fa-download me-2"></i>Get Started
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Quick Access */}
      <section className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">Quick Access</h2>
              <p className="text-muted">Jump directly to what you need</p>
            </div>
          </div>
          
          <div className="row g-4">
            <div className="col-lg-3 col-md-6">
              <div className="quick-link-card text-center p-4 bg-light rounded h-100">
                <i className="fas fa-rocket fa-3x text-primary mb-3"></i>
                <h4>Quick Start</h4>
                <p className="text-muted mb-3">Get up and running in minutes with Docker or native packages.</p>
                <Link href="/download/" className="btn btn-primary">
                  Get Started
                </Link>
              </div>
            </div>
            
            <div className="col-lg-3 col-md-6">
              <div className="quick-link-card text-center p-4 bg-light rounded h-100">
                <i className="fas fa-cogs fa-3x text-success mb-3"></i>
                <h4>Configuration</h4>
                <p className="text-muted mb-3">Learn how to configure Squawk DNS for your environment.</p>
                <a href="https://docs.squawkdns.com/USAGE/" target="_blank" rel="noopener noreferrer" className="btn btn-success">
                  View Guide
                </a>
              </div>
            </div>
            
            <div className="col-lg-3 col-md-6">
              <div className="quick-link-card text-center p-4 bg-light rounded h-100">
                <i className="fas fa-code fa-3x text-warning mb-3"></i>
                <h4>API Reference</h4>
                <p className="text-muted mb-3">Complete API documentation with examples and schemas.</p>
                <a href="https://docs.squawkdns.com/API/" target="_blank" rel="noopener noreferrer" className="btn btn-warning">
                  API Docs
                </a>
              </div>
            </div>
            
            <div className="col-lg-3 col-md-6">
              <div className="quick-link-card text-center p-4 bg-light rounded h-100">
                <i className="fas fa-shield-alt fa-3x text-info mb-3"></i>
                <h4>Security</h4>
                <p className="text-muted mb-3">Security features, mTLS setup, and authentication guides.</p>
                <a href="https://docs.squawkdns.com/ARCHITECTURE/" target="_blank" rel="noopener noreferrer" className="btn btn-info">
                  Security Guide
                </a>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Documentation Sections */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">Documentation Sections</h2>
              <p className="text-muted">Comprehensive guides organized by topic</p>
            </div>
          </div>
          
          <div className="row g-4">
            {/* Getting Started */}
            <div className="col-lg-6">
              <div className="doc-section p-4 bg-white rounded shadow-sm h-100">
                <div className="d-flex align-items-start">
                  <div className="doc-icon bg-primary text-white rounded p-3 me-4">
                    <i className="fas fa-play fa-2x"></i>
                  </div>
                  <div className="flex-grow-1">
                    <h4>Getting Started</h4>
                    <p className="text-muted mb-3">Everything you need to deploy Squawk DNS in your environment.</p>
                    <ul className="list-unstyled">
                      <li className="mb-2">
                        <a href="https://docs.squawkdns.com" target="_blank" rel="noopener noreferrer" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-primary me-2"></i>Installation Guide
                        </a>
                      </li>
                      <li className="mb-2">
                        <a href="https://docs.squawkdns.com/USAGE/" target="_blank" rel="noopener noreferrer" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-primary me-2"></i>Configuration Reference
                        </a>
                      </li>
                      <li className="mb-2">
                        <Link href="/download/" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-primary me-2"></i>Download Options
                        </Link>
                      </li>
                      <li className="mb-2">
                        <a href="https://docs.squawkdns.com/DEVELOPMENT/" target="_blank" rel="noopener noreferrer" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-primary me-2"></i>Development Setup
                        </a>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>

            {/* Architecture & Security */}
            <div className="col-lg-6">
              <div className="doc-section p-4 bg-white rounded shadow-sm h-100">
                <div className="d-flex align-items-start">
                  <div className="doc-icon bg-success text-white rounded p-3 me-4">
                    <i className="fas fa-shield-alt fa-2x"></i>
                  </div>
                  <div className="flex-grow-1">
                    <h4>Architecture & Security</h4>
                    <p className="text-muted mb-3">Deep dive into Squawk DNS architecture and security features.</p>
                    <ul className="list-unstyled">
                      <li className="mb-2">
                        <a href="https://docs.squawkdns.com/ARCHITECTURE/" target="_blank" rel="noopener noreferrer" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-success me-2"></i>System Architecture
                        </a>
                      </li>
                      <li className="mb-2">
                        <a href="https://docs.squawkdns.com/TOKEN_MANAGEMENT/" target="_blank" rel="noopener noreferrer" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-success me-2"></i>Authentication & Authorization
                        </a>
                      </li>
                      <li className="mb-2">
                        <Link href="/features/" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-success me-2"></i>Security Features
                        </Link>
                      </li>
                      <li className="mb-2">
                        <a href="https://docs.squawkdns.com/ARCHITECTURE/#mtls-configuration" target="_blank" rel="noopener noreferrer" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-success me-2"></i>mTLS Configuration
                        </a>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>

            {/* API & Development */}
            <div className="col-lg-6">
              <div className="doc-section p-4 bg-white rounded shadow-sm h-100">
                <div className="d-flex align-items-start">
                  <div className="doc-icon bg-warning text-white rounded p-3 me-4">
                    <i className="fas fa-code fa-2x"></i>
                  </div>
                  <div className="flex-grow-1">
                    <h4>API & Development</h4>
                    <p className="text-muted mb-3">API documentation and development resources for integration.</p>
                    <ul className="list-unstyled">
                      <li className="mb-2">
                        <a href="https://docs.squawkdns.com/API/" target="_blank" rel="noopener noreferrer" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-warning me-2"></i>REST API Reference
                        </a>
                      </li>
                      <li className="mb-2">
                        <a href="https://docs.squawkdns.com/CONTRIBUTING/" target="_blank" rel="noopener noreferrer" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-warning me-2"></i>Contributing Guide
                        </a>
                      </li>
                      <li className="mb-2">
                        <a href="https://github.com/penguincloud/squawk" target="_blank" rel="noopener noreferrer" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-warning me-2"></i>Source Code
                        </a>
                      </li>
                      <li className="mb-2">
                        <a href="https://github.com/penguincloud/squawk/releases" target="_blank" rel="noopener noreferrer" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-warning me-2"></i>Release Notes
                        </a>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>

            {/* Enterprise & Support */}
            <div className="col-lg-6">
              <div className="doc-section p-4 bg-white rounded shadow-sm h-100">
                <div className="d-flex align-items-start">
                  <div className="doc-icon bg-info text-white rounded p-3 me-4">
                    <i className="fas fa-building fa-2x"></i>
                  </div>
                  <div className="flex-grow-1">
                    <h4>Enterprise & Support</h4>
                    <p className="text-muted mb-3">Enterprise deployment guides and support resources.</p>
                    <ul className="list-unstyled">
                      <li className="mb-2">
                        <Link href="/enterprise/" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-info me-2"></i>Enterprise Features
                        </Link>
                      </li>
                      <li className="mb-2">
                        <Link href="/pricing/" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-info me-2"></i>Pricing & Licensing
                        </Link>
                      </li>
                      <li className="mb-2">
                        <a href="https://github.com/penguincloud/squawk/issues" target="_blank" rel="noopener noreferrer" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-info me-2"></i>Community Support
                        </a>
                      </li>
                      <li className="mb-2">
                        <Link href="/contact/" className="text-decoration-none">
                          <i className="fas fa-arrow-right text-info me-2"></i>Enterprise Support
                        </Link>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Code Examples */}
      <section className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">Code Examples</h2>
              <p className="text-muted">Quick examples to get you started</p>
            </div>
          </div>
          
          <div className="row g-4">
            <div className="col-lg-6">
              <div className="code-example p-4 bg-dark text-light rounded">
                <h5 className="text-warning mb-3">
                  <i className="fab fa-docker me-2"></i>Docker Compose (Local Testing)
                </h5>
                <pre className="mb-0"><code>
# Complete local testing environment
git clone https://github.com/penguincloud/squawk.git
cd Squawk

# Set environment variables
export AUTH_TOKEN=your-secure-token
export POSTGRES_PASSWORD=secure-password

# Start full stack (DNS server + client + cache)
docker-compose up -d

# Or start with PostgreSQL and monitoring
docker-compose --profile postgres --profile monitoring up -d
                </code></pre>
              </div>
            </div>
            
            <div className="col-lg-6">
              <div className="code-example p-4 bg-dark text-light rounded">
                <h5 className="text-success mb-3">
                  <i className="fas fa-terminal me-2"></i>Configuration Example
                </h5>
                <pre className="mb-0"><code>
# Environment Variables
export PORT=8080
export AUTH_TOKEN=secure-random-token
export CACHE_ENABLED=true
export CACHE_TTL=300
export ENABLE_BLACKLIST=true
export LOG_LEVEL=INFO

# Start server with custom config
./squawk-dns-server --config config.yaml
                </code></pre>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Support Resources */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">Need Additional Help?</h2>
              <p className="text-muted">Multiple support channels available based on your needs</p>
            </div>
          </div>
          
          <div className="row g-4">
            <div className="col-lg-4">
              <div className="support-option text-center p-4 bg-white rounded shadow-sm h-100">
                <i className="fab fa-github fa-3x text-dark mb-3"></i>
                <h4>Community Support</h4>
                <p className="text-muted mb-3">Free community support via GitHub issues and discussions.</p>
                <a href="https://github.com/penguincloud/squawk/issues" target="_blank" rel="noopener noreferrer" className="btn btn-outline-dark">
                  GitHub Issues
                </a>
              </div>
            </div>
            
            <div className="col-lg-4">
              <div className="support-option text-center p-4 bg-white rounded shadow-sm h-100">
                <i className="fas fa-book fa-3x text-primary mb-3"></i>
                <h4>Documentation Site</h4>
                <p className="text-muted mb-3">Comprehensive documentation with search and examples.</p>
                <a href="https://docs.squawkdns.com" target="_blank" rel="noopener noreferrer" className="btn btn-primary">
                  Browse Docs
                </a>
              </div>
            </div>
            
            <div className="col-lg-4">
              <div className="support-option text-center p-4 bg-white rounded shadow-sm h-100">
                <i className="fas fa-envelope fa-3x text-success mb-3"></i>
                <h4>Enterprise Support</h4>
                <p className="text-muted mb-3">Priority support with SLA guarantees for enterprise customers.</p>
                <a href="mailto:sales@penguincloud.io" className="btn btn-success">
                  Contact Sales
                </a>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Call to Action */}
      <section className="py-5 bg-primary text-white">
        <div className="container">
          <div className="row text-center">
            <div className="col-lg-12">
              <h3 className="fw-bold mb-4">Ready to Get Started?</h3>
              <p className="lead mb-4">
                Choose your deployment method and start securing your DNS infrastructure today.
              </p>
              <div className="d-flex gap-3 justify-content-center flex-wrap">
                <Link href="/download/" className="btn btn-light btn-lg">
                  <i className="fas fa-download me-2"></i>Download Squawk DNS
                </Link>
                <a href="https://docs.squawkdns.com" target="_blank" rel="noopener noreferrer" className="btn btn-outline-light btn-lg">
                  <i className="fas fa-external-link-alt me-2"></i>Full Documentation
                </a>
                <Link href="/enterprise/" className="btn btn-outline-light btn-lg">
                  <i className="fas fa-building me-2"></i>Enterprise Solutions
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>
    </Layout>
  );
}