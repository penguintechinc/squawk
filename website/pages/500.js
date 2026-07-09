import Layout from '../components/Layout';
import Link from 'next/link';

export default function ServerError() {
  return (
    <Layout title="500 - Server Error - Squawk DNS" page="500">
      <section className="py-5 text-center">
        <div className="container">
          <div className="row">
            <div className="col-lg-6 mx-auto">
              <div className="error-content">
                <h1 className="display-1 text-danger">500</h1>
                <h2 className="fw-bold mb-4">Server Error</h2>
                <p className="lead text-muted mb-4">
                  Something went wrong on our end. Please try again later.
                </p>
                
                <div className="error-actions">
                  <Link href="/" className="btn btn-primary btn-lg me-3">
                    <i className="fas fa-home me-2"></i>
                    Go Home
                  </Link>
                  <Link href="/contact" className="btn btn-outline-primary btn-lg">
                    <i className="fas fa-envelope me-2"></i>
                    Contact Support
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </Layout>
  );
}