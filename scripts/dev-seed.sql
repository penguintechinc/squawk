-- DEV/TEST SEED DATA ONLY
-- This script contains predictable test tokens and sample data for development and testing.
-- NEVER mount this file in production.
-- Not referenced by any deployable compose/k8s path.

-- Insert test data for development/testing
INSERT INTO tokens (token, name, description, active) VALUES
    ('test-token-for-development', 'Development Token', 'Token for development and testing', true),
    ('admin-token-12345', 'Admin Token', 'Administrative access token', true),
    ('client-token-67890', 'Client Token', 'Limited client access token', true),
    ('inactive-token', 'Inactive Token', 'Disabled token for testing', false)
ON CONFLICT (token) DO NOTHING;

INSERT INTO domains (name, description) VALUES
    ('*', 'Wildcard - access to all domains'),
    ('example.com', 'Example domain for testing'),
    ('test.com', 'Test domain'),
    ('api.example.com', 'API subdomain'),
    ('internal.company.com', 'Internal company domain'),
    ('dev.example.com', 'Development domain')
ON CONFLICT (name) DO NOTHING;

-- Grant permissions (token_domains relationships)
-- Development token gets wildcard access
INSERT INTO token_domains (token_id, domain_id)
SELECT t.id, d.id
FROM tokens t, domains d
WHERE t.token = 'test-token-for-development'
  AND d.name = '*'
ON CONFLICT DO NOTHING;

-- Admin token gets access to specific domains
INSERT INTO token_domains (token_id, domain_id)
SELECT t.id, d.id
FROM tokens t, domains d
WHERE t.token = 'admin-token-12345'
  AND d.name IN ('example.com', 'api.example.com', 'internal.company.com')
ON CONFLICT DO NOTHING;

-- Client token gets limited access
INSERT INTO token_domains (token_id, domain_id)
SELECT t.id, d.id
FROM tokens t, domains d
WHERE t.token = 'client-token-67890'
  AND d.name IN ('example.com', 'dev.example.com')
ON CONFLICT DO NOTHING;

-- Insert some sample query logs for testing
INSERT INTO query_logs (token_id, domain_queried, query_type, status, client_ip, timestamp)
SELECT
    t.id,
    'example.com',
    'A',
    'allowed',
    '127.0.0.1',
    CURRENT_TIMESTAMP - INTERVAL '1 hour'
FROM tokens t
WHERE t.token = 'test-token-for-development';

INSERT INTO query_logs (token_id, domain_queried, query_type, status, client_ip, timestamp)
SELECT
    t.id,
    'blocked.example.com',
    'A',
    'denied',
    '192.168.1.100',
    CURRENT_TIMESTAMP - INTERVAL '30 minutes'
FROM tokens t
WHERE t.token = 'client-token-67890';
