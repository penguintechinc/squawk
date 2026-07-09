import Layout from '../components/Layout';
import Link from 'next/link';

export default function Contact() {
  return (
    <Layout title="Contact - Squawk DNS" page="contact">
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
              <h1 className="display-4 fw-bold mb-4">Contact Us</h1>
              <p className="lead">
                Get in touch with our team for enterprise sales, technical support, or partnership opportunities.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Contact Options */}
      <section className="py-5">
        <div className="container">
          <div className="row g-4">
            {/* Enterprise Sales */}
            <div className="col-lg-4">
              <div className="contact-card text-center p-5 bg-light rounded shadow-sm h-100">
                <div className="contact-icon bg-primary text-white rounded-circle mx-auto mb-4 d-flex align-items-center justify-content-center" style={{width: '80px', height: '80px'}}>
                  <i className="fas fa-building fa-2x"></i>
                </div>
                <h3 className="mb-3">Enterprise Sales</h3>
                <p className="text-muted mb-4">
                  Ready to deploy Squawk DNS in your enterprise environment? Our sales team is here to help with custom pricing, deployment planning, and enterprise features.
                </p>
                <div className="contact-details mb-4">
                  <p className="mb-2">
                    <strong><i className="fas fa-envelope me-2 text-primary"></i>Email:</strong><br/>
                    <a href="mailto:sales@penguincloud.io" className="text-decoration-none">sales@penguincloud.io</a>
                  </p>
                  <p className="mb-2">
                    <strong><i className="fas fa-clock me-2 text-primary"></i>Response Time:</strong><br/>
                    <span className="text-muted small">4 hours during business days</span>
                  </p>
                </div>
                <a href="mailto:sales@penguincloud.io" className="btn btn-primary btn-lg">
                  <i className="fas fa-envelope me-2"></i>Contact Sales
                </a>
              </div>
            </div>

            {/* Technical Support */}
            <div className="col-lg-4">
              <div className="contact-card text-center p-5 bg-light rounded shadow-sm h-100">
                <div className="contact-icon bg-success text-white rounded-circle mx-auto mb-4 d-flex align-items-center justify-content-center" style={{width: '80px', height: '80px'}}>
                  <i className="fas fa-headset fa-2x"></i>
                </div>
                <h3 className="mb-3">Technical Support</h3>
                <p className="text-muted mb-4">
                  Need help with installation, configuration, or troubleshooting? Our technical support team provides comprehensive assistance for all Squawk DNS deployments.
                </p>
                <div className="contact-details mb-4">
                  <div className="mb-3">
                    <strong>Community Support:</strong><br/>
                    <a href="https://github.com/penguincloud/squawk/issues" target="_blank" rel="noopener noreferrer" className="text-decoration-none">GitHub Issues</a>
                  </div>
                  <div>
                    <strong>Enterprise Support:</strong><br/>
                    <a href="mailto:sales@penguincloud.io" className="text-decoration-none">sales@penguincloud.io</a>
                  </div>
                </div>
                <div className="d-grid gap-2">
                  <a href="https://github.com/penguincloud/squawk/issues" target="_blank" rel="noopener noreferrer" className="btn btn-outline-success">
                    <i className="fab fa-github me-2"></i>Community Support
                  </a>
                  <Link href="/enterprise/" className="btn btn-success">
                    <i className="fas fa-shield-alt me-2"></i>Enterprise Support
                  </Link>
                </div>
              </div>
            </div>

            {/* Partnerships */}
            <div className="col-lg-4">
              <div className="contact-card text-center p-5 bg-light rounded shadow-sm h-100">
                <div className="contact-icon bg-warning text-white rounded-circle mx-auto mb-4 d-flex align-items-center justify-content-center" style={{width: '80px', height: '80px'}}>
                  <i className="fas fa-handshake fa-2x"></i>
                </div>
                <h3 className="mb-3">Partnerships & Integrations</h3>
                <p className="text-muted mb-4">
                  Interested in integrating Squawk DNS into your product or becoming a reseller partner? Let&apos;s discuss collaboration opportunities.
                </p>
                <div className="contact-details mb-4">
                  <p className="mb-2">
                    <strong><i className="fas fa-envelope me-2 text-warning"></i>Email:</strong><br/>
                    <a href="mailto:sales@penguincloud.io" className="text-decoration-none">sales@penguincloud.io</a>
                  </p>
                  <p className="mb-2">
                    <strong><i className="fas fa-users me-2 text-warning"></i>Partnership Types:</strong><br/>
                    <span className="text-muted small">OEM, Reseller, Integration</span>
                  </p>
                </div>
                <a href="mailto:sales@penguincloud.io?subject=Partnership Inquiry" className="btn btn-warning btn-lg">
                  <i className="fas fa-handshake me-2"></i>Partner With Us
                </a>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Company Information */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">About PenguinCloud</h2>
              <p className="text-muted">The company behind Squawk DNS</p>
            </div>
          </div>
          
          <div className="row g-4 justify-content-center">
            <div className="col-lg-8">
              <div className="company-info p-4 bg-white rounded shadow-sm text-center">
                <p className="lead mb-4">
                  PenguinCloud specializes in enterprise security solutions, with a focus on DNS security, 
                  network infrastructure protection, and cloud-native security tools.
                </p>
                
                <div className="row g-4">
                  <div className="col-md-4">
                    <div className="company-stat">
                      <h4 className="text-primary">Enterprise Focus</h4>
                      <p className="text-muted small mb-0">Solutions designed for large-scale deployments</p>
                    </div>
                  </div>
                  <div className="col-md-4">
                    <div className="company-stat">
                      <h4 className="text-success">Open Source</h4>
                      <p className="text-muted small mb-0">Community-driven development model</p>
                    </div>
                  </div>
                  <div className="col-md-4">
                    <div className="company-stat">
                      <h4 className="text-warning">Security First</h4>
                      <p className="text-muted small mb-0">Built with security as the primary focus</p>
                    </div>
                  </div>
                </div>
                
                <div className="mt-4">
                  <div className="company-links d-flex gap-3 justify-content-center flex-wrap">
                    <a href="https://github.com/penguincloud" target="_blank" rel="noopener noreferrer" className="btn btn-outline-dark">
                      <i className="fab fa-github me-2"></i>GitHub
                    </a>
                    <a href="mailto:sales@penguincloud.io" className="btn btn-outline-primary">
                      <i className="fas fa-envelope me-2"></i>General Inquiries
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-lg-12 text-center mb-5">
              <h2 className="fw-bold">Frequently Asked Questions</h2>
              <p className="text-muted">Common questions about support and services</p>
            </div>
          </div>
          
          <div className="row justify-content-center">
            <div className="col-lg-8">
              <div className="accordion" id="contactFAQ">
                <div className="accordion-item">
                  <h2 className="accordion-header">
                    <button className="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#faqContact1">
                      What&apos;s the difference between community and enterprise support?
                    </button>
                  </h2>
                  <div id="faqContact1" className="accordion-collapse collapse show" data-bs-parent="#contactFAQ">
                    <div className="accordion-body">
                      Community support is provided through GitHub issues and is available to all users. Enterprise support includes dedicated support teams, guaranteed response times, phone support, and SLA commitments for paying customers.
                    </div>
                  </div>
                </div>
                
                <div className="accordion-item">
                  <h2 className="accordion-header">
                    <button className="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faqContact2">
                      How quickly can I expect a response to my sales inquiry?
                    </button>
                  </h2>
                  <div id="faqContact2" className="accordion-collapse collapse" data-bs-parent="#contactFAQ">
                    <div className="accordion-body">
                      Our sales team typically responds to inquiries within 4 hours during business days (Monday-Friday, 9 AM - 6 PM EST). For urgent requests, please mention &quot;URGENT&quot; in your subject line.
                    </div>
                  </div>
                </div>

                <div className="accordion-item">
                  <h2 className="accordion-header">
                    <button className="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faqContact3">
                      Do you offer custom development or consulting services?
                    </button>
                  </h2>
                  <div id="faqContact3" className="accordion-collapse collapse" data-bs-parent="#contactFAQ">
                    <div className="accordion-body">
                      Yes! We offer custom feature development, integration consulting, and deployment assistance for enterprise customers. Contact our sales team to discuss your specific requirements and timeline.
                    </div>
                  </div>
                </div>

                <div className="accordion-item">
                  <h2 className="accordion-header">
                    <button className="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faqContact4">
                      Can I schedule a demo or technical discussion?
                    </button>
                  </h2>
                  <div id="faqContact4" className="accordion-collapse collapse" data-bs-parent="#contactFAQ">
                    <div className="accordion-body">
                      Absolutely! We&apos;re happy to schedule demo sessions and technical discussions for potential enterprise customers. Email sales@penguincloud.io with your requirements and preferred time zones.
                    </div>
                  </div>
                </div>
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
              <h3 className="fw-bold mb-4">Ready to Secure Your DNS?</h3>
              <p className="lead mb-4">
                Contact our team today to discuss your DNS security requirements and get started with Squawk DNS.
              </p>
              <div className="d-flex gap-3 justify-content-center flex-wrap">
                <a href="mailto:sales@penguincloud.io" className="btn btn-light btn-lg">
                  <i className="fas fa-envelope me-2"></i>Contact Sales Team
                </a>
                <Link href="/download/" className="btn btn-outline-light btn-lg">
                  <i className="fas fa-download me-2"></i>Try Free Version
                </Link>
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