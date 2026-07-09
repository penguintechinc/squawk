import Head from 'next/head';
import Link from 'next/link';
import Script from 'next/script';
import { useRouter } from 'next/router';
import { useEffect, useState } from 'react';

export default function Layout({ children, title = 'Squawk DNS', page = '' }) {
  const router = useRouter();
  const [version, setVersion] = useState('v1.1.1');

  useEffect(() => {
    // For static export, we'll use a hardcoded version
    // In a real deployment, this could be set via build-time environment variables
    setVersion(process.env.NEXT_PUBLIC_VERSION || 'v1.1.1');
  }, []);

  return (
    <>
      <Head>
        <meta charSet="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>{title}</title>
        <meta name="description" content="Squawk DNS - Secure DNS-over-HTTPS system with enterprise authentication, mTLS support, and comprehensive security features." />
        <meta name="keywords" content="DNS, DNS-over-HTTPS, DoH, security, privacy, mTLS, authentication, enterprise" />
        <meta name="author" content="PenguinCloud" />
        
        {/* Bootstrap CSS */}
        <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/css/bootstrap.min.css" rel="stylesheet" />
        {/* Font Awesome */}
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet" />
        {/* Highlight.js CSS */}
        <link href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css" rel="stylesheet" />
        
        <link rel="icon" href="/favicon.ico" type="image/x-icon" />
      </Head>

      <body>
        {/* Navigation */}
        <nav className="navbar navbar-expand-lg navbar-dark bg-primary sticky-top">
          <div className="container">
            <Link href="/" className="navbar-brand fw-bold">
              <i className="fas fa-shield-alt me-2"></i>
              Squawk DNS
            </Link>
            
            <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
              <span className="navbar-toggler-icon"></span>
            </button>
            
            <div className="collapse navbar-collapse" id="navbarNav">
              <ul className="navbar-nav me-auto">
                <li className="nav-item">
                  <Link href="/" className={`nav-link ${page === 'home' ? 'active' : ''}`}>Home</Link>
                </li>
                <li className="nav-item">
                  <Link href="/features" className={`nav-link ${page === 'features' ? 'active' : ''}`}>Features</Link>
                </li>
                <li className="nav-item">
                  <Link href="/documentation" className={`nav-link ${page === 'documentation' ? 'active' : ''}`}>Documentation</Link>
                </li>
                <li className="nav-item">
                  <Link href="/download" className={`nav-link ${page === 'download' ? 'active' : ''}`}>Download</Link>
                </li>
                <li className="nav-item dropdown">
                  <a className={`nav-link dropdown-toggle ${page === 'pricing' || page === 'enterprise' ? 'active' : ''}`} href="#" role="button" data-bs-toggle="dropdown">
                    Solutions
                  </a>
                  <ul className="dropdown-menu">
                    <li><Link href="/pricing" className="dropdown-item">Pricing</Link></li>
                    <li><Link href="/enterprise" className="dropdown-item">Enterprise</Link></li>
                  </ul>
                </li>
              </ul>
              
              <ul className="navbar-nav">
                <li className="nav-item">
                  <a className="nav-link" href="https://github.com/penguincloud/squawk" target="_blank" rel="noopener noreferrer">
                    <i className="fab fa-github me-1"></i>
                    GitHub
                  </a>
                </li>
                <li className="nav-item">
                  <Link href="/contact" className={`nav-link ${page === 'contact' ? 'active' : ''}`}>Contact</Link>
                </li>
              </ul>
            </div>
          </div>
        </nav>

        {/* Main Content */}
        <main>
          {children}
        </main>

        {/* Footer */}
        <footer className="bg-dark text-light py-5 mt-5">
          <div className="container">
            <div className="row">
              <div className="col-lg-4 mb-4">
                <h5><i className="fas fa-shield-alt me-2"></i>Squawk DNS</h5>
                <p className="text-muted">Secure DNS-over-HTTPS system with enterprise authentication, mTLS support, and comprehensive security features.</p>
                <div className="social-links">
                  <a href="https://github.com/penguincloud/squawk" className="text-light me-3" target="_blank" rel="noopener noreferrer">
                    <i className="fab fa-github fa-lg"></i>
                  </a>
                </div>
              </div>
              
              <div className="col-lg-2 mb-4">
                <h6>Product</h6>
                <ul className="list-unstyled">
                  <li><Link href="/features/" className="text-decoration-none" style={{color: '#6c757d'}}>Features</Link></li>
                  <li><Link href="/pricing/" className="text-decoration-none" style={{color: '#6c757d'}}>Pricing</Link></li>
                  <li><Link href="/enterprise/" className="text-decoration-none" style={{color: '#6c757d'}}>Enterprise</Link></li>
                  <li><Link href="/download/" className="text-decoration-none" style={{color: '#6c757d'}}>Download</Link></li>
                </ul>
              </div>
              
              <div className="col-lg-2 mb-4">
                <h6>Resources</h6>
                <ul className="list-unstyled">
                  <li><Link href="/documentation/" className="text-decoration-none" style={{color: '#6c757d'}}>Documentation</Link></li>
                  <li><a href="https://github.com/penguincloud/squawk/issues" className="text-muted" target="_blank" rel="noopener noreferrer">GitHub Issues</a></li>
                  <li><a href="https://github.com/penguincloud/squawk/releases" className="text-muted" target="_blank" rel="noopener noreferrer">Releases</a></li>
                </ul>
              </div>
              
              <div className="col-lg-2 mb-4">
                <h6>Company</h6>
                <ul className="list-unstyled">
                  <li><Link href="/contact/" className="text-decoration-none" style={{color: '#6c757d'}}>Contact</Link></li>
                  <li><a href="https://support.penguintech.group" className="text-muted" target="_blank" rel="noopener noreferrer">Support</a></li>
                  <li><a href="mailto:sales@penguincloud.io" className="text-muted">Sales</a></li>
                </ul>
              </div>
              
              <div className="col-lg-2 mb-4">
                <h6>Legal</h6>
                <ul className="list-unstyled">
                  <li><a href="https://github.com/penguincloud/squawk/blob/main/LICENSE.md" className="text-muted" target="_blank" rel="noopener noreferrer">License</a></li>
                  <li><span className="text-muted small">AGPL v3</span></li>
                </ul>
              </div>
            </div>
            
            <hr className="my-4" />
            
            <div className="row align-items-center">
              <div className="col-md-8">
                <p className="mb-0 text-muted">&copy; 2025 PenguinCloud. All rights reserved.</p>
              </div>
              <div className="col-md-4 text-md-end">
                <small className="text-muted">Version <span>{version}</span></small>
              </div>
            </div>
          </div>
        </footer>

        {/* Bootstrap JS */}
        <Script 
          src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/js/bootstrap.bundle.min.js"
          strategy="lazyOnload"
        />
      </body>
    </>
  );
}