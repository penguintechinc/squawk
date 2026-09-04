"""Tests for security response headers and error-detail scrubbing."""

from __future__ import annotations


def test_security_headers_on_every_response(client):
    """after_request must stamp security headers even on error responses."""
    resp = client.get('/api/v1/auth/me')  # 401 without a token — still stamped
    assert resp.headers['X-Content-Type-Options'] == 'nosniff'
    assert resp.headers['X-Frame-Options'] == 'DENY'
    assert resp.headers['Content-Security-Policy'] == (
        "default-src 'none'; frame-ancestors 'none'"
    )
    assert resp.headers['Referrer-Policy'] == 'no-referrer'
    assert resp.headers['Strict-Transport-Security'] == (
        'max-age=31536000; includeSubDomains'
    )


def test_internal_error_scrubs_exception_detail(app):
    """internal_error logs the detail but returns only a generic message."""
    from app.utils.responses import internal_error

    secret_detail = "sqlite3.OperationalError: /var/lib/secret/path is locked"
    with app.test_request_context('/api/v1/anything'):
        resp, status = internal_error(Exception(secret_detail))
    assert status == 500
    body = resp.get_json()
    assert body == {'error': 'Internal server error'}
    assert secret_detail not in resp.get_data(as_text=True)
