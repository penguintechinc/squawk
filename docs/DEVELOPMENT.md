# Squawk Development Guide

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Project Structure](#project-structure)
3. [Development Workflow](#development-workflow)
4. [Testing Framework](#testing-framework)
5. [Code Quality Standards](#code-quality-standards)
6. [Database Development](#database-development)
7. [API Development](#api-development)
8. [Frontend Development](#frontend-development)
9. [Debugging and Troubleshooting](#debugging-and-troubleshooting)
10. [Performance Optimization](#performance-optimization)
11. [Security Considerations](#security-considerations)
12. [Release Process](#release-process)

## Development Environment Setup

### Prerequisites

```bash
# System requirements
- Python 3.8 or higher
- Git 2.20+
- SQLite3 (for development)
- Docker 20.10+ with Docker Compose v2 (recommended)
- Ubuntu 22.04 LTS (recommended/tested for Docker builds; other platforms may work)
- Node.js 16+ (for frontend tooling)

# For building from source (optional)
- build-essential
- libxml2-dev, libxslt1-dev (for SAML)
- libldap-dev, libsasl2-dev (for LDAP)
- pkg-config
```

### Quick Setup with Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/penguintechinc/squawk.git
cd Squawk

# Build and start all services
docker-compose up -d --build

# View logs
docker-compose logs -f dns-server

# Run tests in Docker
docker-compose exec dns-server python3 -m pytest tests/
```

### Building Docker Images

```bash
# Build DNS Server (Ubuntu 22.04 based)
cd dns-server
docker build -t squawk-dns-server:dev .

# Build DNS Client (Ubuntu 22.04 based)
cd ../dns-client
docker build -t squawk-dns-client:dev .

# Build with specific features
docker build --build-arg ENABLE_ENTERPRISE=true -t squawk-dns-server:enterprise .
```

### Manual Development Setup

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y \
  python3-dev python3-pip python3-venv \
  build-essential pkg-config \
  libxml2-dev libxslt1-dev \
  libldap-dev libsasl2-dev

# Create virtual environments
cd dns-server
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip wheel setuptools

# Install with fallback for enterprise features
pip install -r requirements.txt || \
  (echo "Enterprise features failed, using base requirements" && \
   pip install -r requirements-base.txt)

pip install -r requirements-dev.txt

cd ../dns-client
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip wheel setuptools
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### IDE Configuration

#### VS Code Setup

```json
// .vscode/settings.json
{
    "python.defaultInterpreterPath": "./dns-server/venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.mypyEnabled": true,
    "[python]": {
        "editor.defaultFormatter": "charliermarsh.ruff",
        "editor.formatOnSave": true
    },
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": ["tests/"],
    "files.exclude": {
        "**/__pycache__": true,
        "**/*.pyc": true,
        "**/venv": true,
        "**/.pytest_cache": true
    }
}
```

#### PyCharm Setup

```python
# PyCharm configuration
- Interpreter: Project venv Python
- Code style: ruff format (120 char line length, see pyproject.toml)
- Test runner: pytest
- Type checker: mypy
- Linter: ruff
```

### Environment Variables

```bash
# .env.development
export SQUAWK_ENV=development
export SQUAWK_DEBUG=true
export SQUAWK_PORT=8080
export SQUAWK_CONSOLE_PORT=8000
export DB_URL=sqlite:///dev.db
export LOG_LEVEL=DEBUG
export USE_NEW_AUTH=true

# Load environment
source .env.development
```

## Project Structure

### Directory Layout

```
Squawk/
├── dns-server/                 # DNS server component
│   ├── bins/                  # Executable scripts
│   │   └── server.py         # Main DNS server
│   ├── libs/                 # Shared libraries
│   │   ├── __init__.py
│   │   ├── dns_utils.py      # DNS utility functions
│   │   ├── auth.py           # Authentication helpers
│   │   └── validators.py     # Input validation
│   ├── tests/                # Server tests
│   │   ├── unit/             # Unit tests
│   │   ├── integration/      # Integration tests
│   │   ├── security/         # Security tests
│   │   └── fixtures/         # Test data
│   ├── web/                  # Py4web applications
│   │   └── apps/
│   │       └── dns_console/  # Web console app
│   ├── requirements.txt      # Production dependencies
│   ├── requirements-dev.txt  # Development dependencies
│   └── venv/                # Virtual environment
├── dns-client/               # DNS client component
│   ├── bins/                # Client executables
│   │   ├── client.py        # Main client
│   │   └── k8s-client.py    # Kubernetes client
│   ├── libs/                # Client libraries
│   │   ├── __init__.py
│   │   ├── client.py        # DoH client library
│   │   ├── forwarder.py     # DNS forwarder
│   │   └── config.py        # Configuration management
│   ├── tests/               # Client tests
│   └── venv/               # Virtual environment
├── docs/                    # Documentation
│   ├── USAGE.md            # Usage guide
│   ├── CONTRIBUTING.md     # Contribution guide
│   ├── ARCHITECTURE.md     # Architecture docs
│   ├── DEVELOPMENT.md      # This file
│   └── API.md              # API documentation
├── scripts/                # Build and deployment scripts
│   ├── setup-dev.sh        # Development setup
│   ├── run-tests.sh        # Test runner
│   ├── build.sh           # Build script
│   └── deploy.sh          # Deployment script
├── docker/                 # Docker configurations
│   ├── Dockerfile.server   # Server container
│   ├── Dockerfile.client   # Client container
│   └── docker-compose.dev.yml
├── .github/               # GitHub workflows
│   └── workflows/
│       ├── ci.yml         # Continuous integration
│       └── release.yml    # Release automation
├── Makefile              # Development commands
├── pyproject.toml        # Python project config
├── claude.md            # AI assistant context
└── README.md            # Project overview
```

### Module Organization

#### DNS Server Modules

```python
# dns-server/libs/dns_utils.py
def validate_domain(domain: str) -> bool:
    """Validate domain name format"""

def format_dns_response(answer: List[str], status: int) -> Dict:
    """Format DNS response as JSON"""

def parse_dns_query(query_string: str) -> Tuple[str, str]:
    """Parse DNS query parameters"""
```

```python
# dns-server/libs/auth.py
class TokenManager:
    """Handle token operations"""

    def validate_token(self, token: str) -> Optional[Dict]:
        """Validate authentication token"""

    def check_permissions(self, token_id: int, domain: str) -> bool:
        """Check domain permissions"""
```

```python
# dns-server/libs/validators.py
def validate_token_format(token: str) -> bool:
    """Validate token format"""

def validate_domain_name(domain: str) -> bool:
    """Validate domain name"""

def sanitize_input(user_input: str) -> str:
    """Sanitize user input"""
```

#### DNS Client Modules

```python
# dns-client/libs/client.py
class DNSOverHTTPSClient:
    """DoH client implementation"""

    def query(self, domain: str, record_type: str = "A") -> Dict:
        """Perform DNS query"""

    def set_auth_token(self, token: str) -> None:
        """Set authentication token"""
```

```python
# dns-client/libs/forwarder.py
class DNSForwarder:
    """Local DNS forwarding service"""

    def start_udp_server(self) -> None:
        """Start UDP DNS server"""

    def start_tcp_server(self) -> None:
        """Start TCP DNS server"""
```

## Development Workflow

### Feature Development Process

```bash
# 1. Create feature branch
git checkout -b feature/token-expiry
git push -u origin feature/token-expiry

# 2. Implement feature
# Edit code, write tests, update docs

# 3. Run local tests
make test
make lint
make type-check

# 4. Commit changes
git add .
git commit -m "feat: add token expiry functionality

- Add expiry field to tokens table
- Implement expiry validation in auth
- Add UI for setting token expiry
- Update API documentation

Closes #123"

# 5. Push and create PR
git push
gh pr create --title "Add token expiry functionality" --body "Implements token expiration feature as requested in #123"
```

### Code Review Process

```bash
# Before submitting PR:
1. [ ] All tests pass
2. [ ] Code coverage > 80%
3. [ ] No linting errors
4. [ ] Type checking passes
5. [ ] Documentation updated
6. [ ] Security review completed
7. [ ] Performance impact assessed

# Review checklist:
1. [ ] Code follows style guidelines
2. [ ] Logic is correct and efficient
3. [ ] Error handling is appropriate
4. [ ] Tests are comprehensive
5. [ ] Documentation is clear
6. [ ] Security implications reviewed
7. [ ] Breaking changes documented
```

### Commit Message Convention

```bash
# Format: <type>(<scope>): <subject>

# Types:
feat:     # New feature
fix:      # Bug fix
docs:     # Documentation only changes
style:    # Formatting, missing semicolons, etc
refactor: # Code change that neither fixes bug nor adds feature
perf:     # Performance improvement
test:     # Adding missing tests
chore:    # Changes to build process or auxiliary tools

# Examples:
feat(auth): add token expiry functionality
fix(server): resolve DNS timeout issue
docs(api): update authentication endpoints
test(client): add integration tests for forwarder
```

## Testing Framework

### Test Structure

```python
# tests/conftest.py
import pytest
from dns_server.libs.auth import TokenManager
from dns_client.libs.client import DNSOverHTTPSClient

@pytest.fixture
def token_manager():
    """Token manager fixture"""
    return TokenManager(db_url="sqlite:///:memory:")

@pytest.fixture
def dns_client():
    """DNS client fixture"""
    return DNSOverHTTPSClient("http://localhost:8080", "test-token")

@pytest.fixture
def sample_token():
    """Sample token for testing"""
    return {
        'id': 1,
        'token': 'test-token-12345',
        'name': 'Test Token',
        'active': True,
        'domains': ['example.com', '*.test.com']
    }
```

### Unit Testing

```python
# tests/unit/test_auth.py
import pytest
from unittest.mock import Mock, patch
from dns_server.libs.auth import TokenManager

class TestTokenManager:
    def test_validate_token_success(self, token_manager, sample_token):
        """Test successful token validation"""
        with patch.object(token_manager, 'get_token') as mock_get:
            mock_get.return_value = sample_token

            result = token_manager.validate_token('test-token-12345')

            assert result is not None
            assert result['name'] == 'Test Token'
            mock_get.assert_called_once_with('test-token-12345')

    def test_validate_token_not_found(self, token_manager):
        """Test token not found"""
        with patch.object(token_manager, 'get_token') as mock_get:
            mock_get.return_value = None

            result = token_manager.validate_token('invalid-token')

            assert result is None

    @pytest.mark.parametrize("domain,expected", [
        ("example.com", True),
        ("sub.example.com", True),
        ("test.com", True),
        ("other.com", False),
    ])
    def test_check_permissions(self, token_manager, sample_token, domain, expected):
        """Test permission checking"""
        result = token_manager.check_permissions(sample_token['id'], domain)
        assert result == expected
```

### Integration Testing

```python
# tests/integration/test_end_to_end.py
import pytest
import requests
from dns_server.bins.server import main as server_main
from dns_client.libs.client import DNSOverHTTPSClient

class TestEndToEnd:
    @pytest.fixture(scope="class")
    def running_server(self):
        """Start DNS server for testing"""
        # Start server in background thread
        pass

    def test_dns_query_with_valid_token(self, running_server):
        """Test complete DNS query flow"""
        client = DNSOverHTTPSClient("http://localhost:8080", "valid-test-token")

        response = client.query("example.com", "A")

        assert response['Status'] == 0
        assert 'Answer' in response
        assert len(response['Answer']) > 0

    def test_dns_query_with_invalid_token(self, running_server):
        """Test DNS query with invalid token"""
        client = DNSOverHTTPSClient("http://localhost:8080", "invalid-token")

        with pytest.raises(requests.exceptions.HTTPError) as exc_info:
            client.query("example.com", "A")

        assert exc_info.value.response.status_code == 403
```

### Security Testing

```python
# tests/security/test_injection.py
import pytest
from dns_server.libs.auth import TokenManager

class TestSecurityInjection:
    def test_sql_injection_token(self, token_manager):
        """Test SQL injection in token validation"""
        malicious_tokens = [
            "'; DROP TABLE tokens; --",
            "' OR '1'='1",
            "admin'/**/AND/**/1=1--",
        ]

        for token in malicious_tokens:
            result = token_manager.validate_token(token)
            assert result is None  # Should not succeed

    def test_domain_validation_bypass(self):
        """Test domain validation bypass attempts"""
        from dns_server.libs.validators import validate_domain_name

        bypass_attempts = [
            "../admin.example.com",
            "example.com/../admin",
            "example.com\x00admin.com",
            "example.com;admin.com",
        ]

        for attempt in bypass_attempts:
            assert not validate_domain_name(attempt)

    def test_xss_prevention(self):
        """Test XSS prevention in web console"""
        malicious_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
        ]

        for input_str in malicious_inputs:
            # Test that input is properly escaped
            pass
```

### Performance Testing

```python
# tests/performance/test_load.py
import pytest
import time
import concurrent.futures
from dns_client.libs.client import DNSOverHTTPSClient

class TestPerformance:
    def test_concurrent_queries(self):
        """Test performance under concurrent load"""
        client = DNSOverHTTPSClient("http://localhost:8080", "test-token")

        def make_query():
            return client.query("example.com", "A")

        start_time = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(make_query) for _ in range(100)]
            results = [f.result() for f in futures]

        end_time = time.time()

        # Assertions
        assert len(results) == 100
        assert all(r['Status'] == 0 for r in results)
        assert end_time - start_time < 10  # Should complete within 10 seconds

    def test_memory_usage(self):
        """Test memory usage during operation"""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        client = DNSOverHTTPSClient("http://localhost:8080", "test-token")

        # Make many queries
        for _ in range(1000):
            client.query("example.com", "A")

        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        # Memory increase should be reasonable (< 50MB)
        assert memory_increase < 50 * 1024 * 1024
```

### Running Tests

```bash
# Run all tests
make test

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
pytest tests/security/
pytest tests/performance/

# Run with coverage
pytest --cov=dns_server --cov=dns_client --cov-report=html

# Run tests in parallel
pytest -n auto

# Run tests with verbose output
pytest -v

# Run specific test file
pytest tests/unit/test_auth.py

# Run tests matching pattern
pytest -k "test_token"

# Run tests with debugging
pytest --pdb
```

## Code Quality Standards

### Linting Configuration

ruff supersedes flake8/black/isort (one tool for lint + import-sort + format).
See the actual, current config in `pyproject.toml` at the repo root:

```toml
# pyproject.toml (excerpt -- see the real file for the full, current config)
[tool.ruff]
target-version = "py313"
line-length = 120

[tool.ruff.lint]
select = ["E", "W", "F", "I", "N", "D", "UP", "B", "ASYNC", "S"]

[tool.ruff.lint.pydocstyle]
convention = "google"

[tool.mypy]
python_version = "3.13"
warn_return_any = true
warn_unused_configs = true
warn_unused_ignores = true
check_untyped_defs = false
no_implicit_optional = true
warn_redundant_casts = true
warn_no_return = true
```

### Pre-commit Hooks

See the actual, current hook set in `.pre-commit-config.yaml` at the repo
root -- this is illustrative only, and will drift if hand-copied:

```yaml
# .pre-commit-config.yaml (excerpt)
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-merge-conflict

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.8.4
    hooks:
      - id: ruff
        args: [--select=F,E9,B, --fix]
      - id: ruff-format
        stages: [manual]

  - repo: local
    hooks:
      - id: mypy
        name: Type check with mypy (advisory, run via make type-check)
        stages: [manual]
```

### Code Documentation Standards

```python
def authenticate_token(token: str, domain: str, db_connection) -> bool:
    """Authenticate token for domain access.

    Validates the provided authentication token and checks if it has
    permission to access the specified domain. Supports both exact
    domain matching and wildcard permissions.

    Args:
        token: The authentication token to validate. Must be a valid
            base64url encoded string of at least 32 characters.
        domain: The domain name being accessed. Must be a valid FQDN
            or subdomain following RFC 1035 standards.
        db_connection: Database connection object for token lookup.
            Should be an active SQLite, PostgreSQL, or MySQL connection.

    Returns:
        True if the token is valid and has permission for the domain,
        False otherwise.

    Raises:
        ValueError: If token format is invalid or domain is malformed.
        DatabaseError: If database connection fails or query errors occur.
        AuthenticationError: If token validation process fails.

    Example:
        >>> db = sqlite3.connect(':memory:')
        >>> authenticate_token('abc123def456', 'example.com', db)
        True
        >>> authenticate_token('invalid', 'example.com', db)
        False

    Note:
        This function performs timing-attack resistant token comparison
        and logs all authentication attempts for security auditing.
    """
    # Implementation here
    pass
```

## Database Development

### Migration System

```python
# migrations/001_initial_schema.py
def up(db):
    """Create initial database schema"""
    db.executesql('''
        CREATE TABLE tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token VARCHAR(255) UNIQUE NOT NULL,
            name VARCHAR(100) NOT NULL,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_used DATETIME,
            active BOOLEAN DEFAULT TRUE
        )
    ''')

    db.executesql('''
        CREATE TABLE domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(255) UNIQUE NOT NULL,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    db.executesql('''
        CREATE TABLE token_domains (
            token_id INTEGER REFERENCES tokens(id) ON DELETE CASCADE,
            domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (token_id, domain_id)
        )
    ''')

def down(db):
    """Drop tables"""
    db.executesql('DROP TABLE IF EXISTS token_domains')
    db.executesql('DROP TABLE IF EXISTS domains')
    db.executesql('DROP TABLE IF EXISTS tokens')
```

```python
# migrations/002_add_query_logs.py
def up(db):
    """Add query logging table"""
    db.executesql('''
        CREATE TABLE query_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id INTEGER REFERENCES tokens(id) ON DELETE SET NULL,
            domain_queried VARCHAR(255) NOT NULL,
            query_type VARCHAR(10),
            status VARCHAR(20),
            client_ip VARCHAR(45),
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Add indexes for performance
    db.executesql('CREATE INDEX idx_query_logs_timestamp ON query_logs(timestamp DESC)')
    db.executesql('CREATE INDEX idx_query_logs_token ON query_logs(token_id)')

def down(db):
    """Remove query logging table"""
    db.executesql('DROP TABLE IF EXISTS query_logs')
```

### Database Testing

```python
# tests/unit/test_database.py
import pytest
from pydal import DAL, Field

@pytest.fixture
def test_db():
    """Test database fixture"""
    db = DAL('sqlite://test.db')

    # Define tables
    db.define_table('tokens',
        Field('token', 'string'),
        Field('name', 'string'),
        Field('active', 'boolean', default=True)
    )

    yield db

    # Cleanup
    db.close()

def test_token_creation(test_db):
    """Test token creation"""
    token_id = test_db.tokens.insert(
        token='test-token-123',
        name='Test Token'
    )

    assert token_id is not None

    token = test_db.tokens[token_id]
    assert token.token == 'test-token-123'
    assert token.name == 'Test Token'
    assert token.active is True

def test_token_uniqueness(test_db):
    """Test token uniqueness constraint"""
    test_db.tokens.insert(token='duplicate-token', name='Token 1')

    with pytest.raises(Exception):  # Should raise constraint violation
        test_db.tokens.insert(token='duplicate-token', name='Token 2')
```

## API Development

### API Design Principles

```python
# RESTful API design
GET    /api/v1/tokens              # List all tokens
POST   /api/v1/tokens              # Create new token
GET    /api/v1/tokens/{id}         # Get specific token
PUT    /api/v1/tokens/{id}         # Update token
DELETE /api/v1/tokens/{id}         # Delete token
PATCH  /api/v1/tokens/{id}/status  # Toggle token status

# Domain management
GET    /api/v1/domains             # List all domains
POST   /api/v1/domains             # Add new domain
DELETE /api/v1/domains/{id}        # Remove domain

# Permission management
GET    /api/v1/permissions         # List all permissions
POST   /api/v1/permissions         # Grant permission
DELETE /api/v1/permissions/{token_id}/{domain_id}  # Revoke permission
```

### API Response Standards

```python
# Success responses
{
    "success": true,
    "data": {
        "id": 123,
        "token": "abc123",
        "name": "My Token"
    },
    "message": "Token created successfully"
}

# Error responses
{
    "success": false,
    "error": {
        "code": "VALIDATION_ERROR",
        "message": "Token name is required",
        "details": {
            "field": "name",
            "constraint": "not_empty"
        }
    }
}

# List responses
{
    "success": true,
    "data": [
        {"id": 1, "name": "Token 1"},
        {"id": 2, "name": "Token 2"}
    ],
    "pagination": {
        "page": 1,
        "per_page": 20,
        "total": 45,
        "pages": 3
    }
}
```

### API Testing

```python
# tests/integration/test_api.py
import pytest
import requests

class TestTokenAPI:
    def test_create_token(self, api_base_url):
        """Test token creation API"""
        payload = {
            "name": "Test API Token",
            "description": "Created via API test"
        }

        response = requests.post(f"{api_base_url}/tokens", json=payload)

        assert response.status_code == 201
        data = response.json()
        assert data["success"] is True
        assert "token" in data["data"]
        assert data["data"]["name"] == "Test API Token"

    def test_list_tokens(self, api_base_url, sample_tokens):
        """Test token listing API"""
        response = requests.get(f"{api_base_url}/tokens")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert len(data["data"]) >= len(sample_tokens)

    def test_invalid_token_creation(self, api_base_url):
        """Test invalid token creation"""
        payload = {}  # Missing required fields

        response = requests.post(f"{api_base_url}/tokens", json=payload)

        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
        assert "error" in data
```

## Frontend Development

### Py4web Templates

```html
<!-- templates/layout.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>[[=title or "DNS Console"]] - Squawk</title>

    <!-- CSS Framework -->
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <!-- Custom CSS -->
    <link href="[[=URL('static', 'css/app.css')]]" rel="stylesheet">
</head>
<body class="bg-gray-50">
    <nav class="bg-blue-600 text-white p-4">
        <div class="container mx-auto flex justify-between items-center">
            <h1 class="text-xl font-bold">Squawk DNS Console</h1>
            <div class="space-x-4">
                <a href="[[=URL('index')]]" class="hover:text-blue-200">Dashboard</a>
                <a href="[[=URL('tokens')]]" class="hover:text-blue-200">Tokens</a>
                <a href="[[=URL('domains')]]" class="hover:text-blue-200">Domains</a>
                <a href="[[=URL('permissions')]]" class="hover:text-blue-200">Permissions</a>
                <a href="[[=URL('logs')]]" class="hover:text-blue-200">Logs</a>
            </div>
        </div>
    </nav>

    <main class="container mx-auto mt-8 px-4">
        [[if flash:]]
        <div class="bg-blue-100 border-l-4 border-blue-500 text-blue-700 p-4 mb-6" role="alert">
            [[=flash]]
        </div>
        [[pass]]

        [[include]]
    </main>

    <!-- JavaScript -->
    <script src="[[=URL('static', 'js/app.js')]]"></script>
</body>
</html>
```

### JavaScript Frontend

```javascript
// static/js/app.js
class SquawkConsole {
    constructor() {
        this.baseUrl = '/dns_console/api';
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadDashboardData();
    }

    setupEventListeners() {
        // Permission matrix checkboxes
        document.addEventListener('change', (e) => {
            if (e.target.classList.contains('permission-checkbox')) {
                this.togglePermission(e.target);
            }
        });

        // Token form submission
        const tokenForm = document.getElementById('token-form');
        if (tokenForm) {
            tokenForm.addEventListener('submit', (e) => {
                this.handleTokenSubmit(e);
            });
        }
    }

    async togglePermission(checkbox) {
        const tokenId = checkbox.dataset.tokenId;
        const domainId = checkbox.dataset.domainId;

        try {
            const response = await fetch(`${this.baseUrl}/permissions/toggle`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    token_id: tokenId,
                    domain_id: domainId
                })
            });

            const result = await response.json();

            if (result.success) {
                checkbox.checked = result.new_state;
                this.showNotification('Permission updated successfully', 'success');
            } else {
                checkbox.checked = !checkbox.checked; // Revert
                this.showNotification(`Error: ${result.error}`, 'error');
            }
        } catch (error) {
            checkbox.checked = !checkbox.checked; // Revert
            this.showNotification('Network error occurred', 'error');
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 p-4 rounded-md shadow-md z-50 ${
            type === 'success' ? 'bg-green-500' :
            type === 'error' ? 'bg-red-500' : 'bg-blue-500'
        } text-white`;
        notification.textContent = message;

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.remove();
        }, 3000);
    }

    async loadDashboardData() {
        try {
            const response = await fetch(`${this.baseUrl}/stats`);
            const data = await response.json();

            if (data.success) {
                this.updateDashboardStats(data.data);
            }
        } catch (error) {
            console.error('Failed to load dashboard data:', error);
        }
    }

    updateDashboardStats(stats) {
        const elements = {
            tokenCount: document.getElementById('token-count'),
            domainCount: document.getElementById('domain-count'),
            queryCount: document.getElementById('query-count')
        };

        if (elements.tokenCount) {
            elements.tokenCount.textContent = stats.tokens;
        }
        if (elements.domainCount) {
            elements.domainCount.textContent = stats.domains;
        }
        if (elements.queryCount) {
            elements.queryCount.textContent = stats.queries;
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SquawkConsole();
});
```

## Debugging and Troubleshooting

### Debug Configuration

```python
# debug.py - Debug utilities
import logging
import sys
from typing import Any, Dict

# Configure debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('debug.log')
    ]
)

def debug_request(handler_instance):
    """Debug HTTP request details"""
    logger = logging.getLogger('request_debug')
    logger.debug(f"Path: {handler_instance.path}")
    logger.debug(f"Method: {handler_instance.command}")
    logger.debug(f"Headers: {dict(handler_instance.headers)}")
    logger.debug(f"Client: {handler_instance.client_address}")

def debug_database_query(query: str, params: tuple = None):
    """Debug database queries"""
    logger = logging.getLogger('db_debug')
    logger.debug(f"Query: {query}")
    if params:
        logger.debug(f"Parameters: {params}")

def debug_token_validation(token: str, domain: str, result: bool):
    """Debug token validation process"""
    logger = logging.getLogger('auth_debug')
    logger.debug(f"Token: {token[:8]}... (truncated)")
    logger.debug(f"Domain: {domain}")
    logger.debug(f"Result: {result}")
```

### Common Issues and Solutions

```python
# troubleshooting.py
class TroubleshootingGuide:
    """Common issues and their solutions"""

    @staticmethod
    def diagnose_auth_failure(token: str, domain: str) -> Dict[str, Any]:
        """Diagnose authentication failures"""
        issues = []

        # Check token format
        if len(token) < 32:
            issues.append("Token too short - should be at least 32 characters")

        # Check domain format
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            issues.append("Invalid domain format")

        # Check database connection
        try:
            # Test database connection
            pass
        except Exception as e:
            issues.append(f"Database connection failed: {e}")

        return {
            'token_format_valid': len(token) >= 32,
            'domain_format_valid': bool(re.match(r'^[a-zA-Z0-9.-]+$', domain)),
            'issues': issues,
            'suggestions': [
                "Verify token is active in web console",
                "Check domain permissions are assigned",
                "Review server logs for detailed errors"
            ]
        }

    @staticmethod
    def check_server_health() -> Dict[str, Any]:
        """Check server health status"""
        return {
            'database_connection': True,
            'upstream_dns_reachable': True,
            'memory_usage_mb': 128,
            'active_connections': 15
        }
```

### Performance Debugging

```python
# performance.py
import time
import functools
from typing import Callable

def timing_decorator(func: Callable) -> Callable:
    """Decorator to measure function execution time"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()

        logger = logging.getLogger('performance')
        logger.debug(f"{func.__name__} took {end_time - start_time:.4f} seconds")

        return result
    return wrapper

@timing_decorator
def validate_token_with_timing(token: str, domain: str) -> bool:
    """Token validation with performance timing"""
    # Implementation here
    pass

class PerformanceMonitor:
    """Monitor performance metrics"""

    def __init__(self):
        self.metrics = {}

    def record_request(self, duration: float, status_code: int):
        """Record request metrics"""
        if status_code not in self.metrics:
            self.metrics[status_code] = []

        self.metrics[status_code].append(duration)

    def get_stats(self) -> Dict[str, float]:
        """Get performance statistics"""
        stats = {}

        for status_code, durations in self.metrics.items():
            stats[f'avg_time_{status_code}'] = sum(durations) / len(durations)
            stats[f'max_time_{status_code}'] = max(durations)
            stats[f'min_time_{status_code}'] = min(durations)
            stats[f'requests_{status_code}'] = len(durations)

        return stats
```

## Performance Optimization

### Database Optimization

```sql
-- Performance indexes
CREATE INDEX CONCURRENTLY idx_tokens_active_token ON tokens(active, token) WHERE active = true;
CREATE INDEX CONCURRENTLY idx_query_logs_timestamp_desc ON query_logs(timestamp DESC);
CREATE INDEX CONCURRENTLY idx_token_domains_covering ON token_domains(token_id, domain_id);

-- Analyze table statistics
ANALYZE tokens;
ANALYZE domains;
ANALYZE token_domains;
ANALYZE query_logs;

-- Vacuum for SQLite
VACUUM;

-- For PostgreSQL
VACUUM ANALYZE;
```

### Caching Strategy

```python
# caching.py
import time
from typing import Dict, Any, Optional
from functools import lru_cache

class TokenPermissionCache:
    """Cache for token permissions"""

    def __init__(self, ttl: int = 300):  # 5 minute TTL
        self.cache = {}
        self.ttl = ttl

    def get(self, token: str, domain: str) -> Optional[bool]:
        """Get cached permission result"""
        key = f"{token}:{domain}"

        if key in self.cache:
            result, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return result
            else:
                del self.cache[key]

        return None

    def set(self, token: str, domain: str, result: bool) -> None:
        """Cache permission result"""
        key = f"{token}:{domain}"
        self.cache[key] = (result, time.time())

    def invalidate(self, token: str = None) -> None:
        """Invalidate cache entries"""
        if token:
            # Invalidate specific token
            keys_to_delete = [k for k in self.cache.keys() if k.startswith(f"{token}:")]
            for key in keys_to_delete:
                del self.cache[key]
        else:
            # Clear entire cache
            self.cache.clear()

# Use LRU cache for frequently accessed functions
@lru_cache(maxsize=1000)
def validate_domain_format(domain: str) -> bool:
    """Cached domain format validation"""
    import re
    pattern = re.compile(r'^[a-zA-Z0-9.-]+$')
    return bool(pattern.match(domain))
```

## Security Considerations

### Input Sanitization

```python
# security.py
import html
import re
from typing import str

def sanitize_domain_input(domain: str) -> str:
    """Sanitize domain name input"""
    # Remove dangerous characters
    domain = re.sub(r'[^a-zA-Z0-9.-]', '', domain)

    # Limit length
    domain = domain[:253]  # Max domain length per RFC

    # Remove leading/trailing dots
    domain = domain.strip('.')

    return domain.lower()

def sanitize_html_input(user_input: str) -> str:
    """Sanitize HTML input to prevent XSS"""
    # Escape HTML entities
    sanitized = html.escape(user_input)

    # Remove potentially dangerous protocols
    dangerous_patterns = [
        r'javascript:',
        r'data:',
        r'vbscript:',
    ]

    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)

    return sanitized

def validate_token_format(token: str) -> bool:
    """Validate token format"""
    # Check length
    if len(token) < 32 or len(token) > 128:
        return False

    # Check character set (base64url)
    if not re.match(r'^[A-Za-z0-9_-]+$', token):
        return False

    return True
```

### Rate Limiting

```python
# rate_limiting.py
import time
from collections import defaultdict, deque
from typing import Dict, Deque

class RateLimiter:
    """Token bucket rate limiter"""

    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.requests: Dict[str, Deque[float]] = defaultdict(deque)

    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed"""
        now = time.time()
        minute_ago = now - 60

        # Clean old requests
        request_times = self.requests[identifier]
        while request_times and request_times[0] < minute_ago:
            request_times.popleft()

        # Check if under limit
        if len(request_times) < self.requests_per_minute:
            request_times.append(now)
            return True

        return False

# Usage in DNS handler
rate_limiter = RateLimiter(requests_per_minute=100)

def check_rate_limit(self, client_ip: str) -> bool:
    """Check rate limit for client"""
    return rate_limiter.is_allowed(client_ip)
```

## Observability & Monitoring

### OpenTelemetry Tracing

Squawk includes opt-in OpenTelemetry (OTel) tracing for both the manager control plane and DNS server data plane. Tracing is completely disabled by default (zero overhead) and only initializes when explicitly enabled.

#### Enabling Tracing

Set the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable to enable tracing:

```bash
# Enable tracing with OTLP HTTP exporter
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318

# Start the manager
python3 -m app

# Start the DNS server
python3 -m app.main
```

If the env var is not set, the applications boot normally with **no tracing overhead** — the OpenTelemetry SDK is not even initialized.

#### Tracing Configuration

**Common environment variables:**

| Variable | Purpose | Default |
|----------|---------|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP HTTP collector endpoint (e.g., `http://localhost:4318`) | Not set (tracing disabled) |
| `OTEL_TRACES_SAMPLER` | Trace sampling strategy: `always_on`, `always_off`, or `parentbased_*` | `always_on` (if tracing enabled) |
| `OTEL_TRACES_SAMPLER_ARG` | Argument for sampler (e.g., `0.5` for 50% sampling) | Depends on sampler |
| `OTEL_SERVICE_NAME` | Override service name | `squawk-manager` or `squawk-dns-server` |

#### Instrumented Components

**Manager (Flask):**
- Flask request/response handling
- Outbound HTTP requests (via `requests` library)
- W3C trace context propagation (automatic)

**DNS Server (Quart/ASGI):**
- ASGI middleware for request handling
- Outbound HTTP requests (via `requests` library)
- W3C trace context propagation (automatic)

#### What's Captured in Traces

- **Span attributes:** HTTP method, URL, status code, response time
- **Service metadata:** `service.name`, `service.version`
- **Trace context:** Parent-child span relationships via W3C `traceparent` header

#### Testing with Jaeger (Local Development)

```bash
# Start Jaeger all-in-one container
docker run -d \
  --name jaeger \
  -e COLLECTOR_OTLP_ENABLED=true \
  -p 4318:4318 \
  -p 16686:16686 \
  jaegertracing/all-in-one

# Enable tracing in Squawk
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318

# Start manager and DNS server (they will send traces to Jaeger)

# View traces at http://localhost:16686
```

#### Sampling for Production

To reduce trace volume in production, configure sampling:

```bash
# 10% sampling
export OTEL_TRACES_SAMPLER=parentbased_traceidratio
export OTEL_TRACES_SAMPLER_ARG=0.1

# Disable tracing
unset OTEL_EXPORTER_OTLP_ENDPOINT
```

#### Logs vs Metrics vs Traces

Squawk separates observability signals:

- **Logs:** Structured JSON logs via Python `logging` module (separate from tracing)
- **Metrics:** Prometheus metrics via `prometheus-client` (separate from tracing)
- **Traces:** OpenTelemetry traces (this section)

Each signal is independent; enable/disable them as needed without affecting the others.

## Release Process

### Version Management

```bash
# Semantic versioning
MAJOR.MINOR.PATCH

# Example versions:
1.0.0  # Initial release
1.0.1  # Patch release (bug fixes)
1.1.0  # Minor release (new features, backward compatible)
2.0.0  # Major release (breaking changes)
```

### Release Checklist

```markdown
## Pre-release Checklist

- [ ] All tests pass (unit, integration, security)
- [ ] Code coverage > 80%
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version number bumped
- [ ] Security scan completed
- [ ] Performance regression tests passed
- [ ] Breaking changes documented
- [ ] Migration scripts tested
- [ ] Deployment scripts updated

## Release Process

1. [ ] Create release branch: `git checkout -b release/v1.2.0`
2. [ ] Update version in all relevant files
3. [ ] Run full test suite: `make test-all`
4. [ ] Update CHANGELOG.md with release notes
5. [ ] Commit changes: `git commit -m "chore: prepare v1.2.0 release"`
6. [ ] Create pull request for review
7. [ ] Merge to main after approval
8. [ ] Create git tag: `git tag v1.2.0`
9. [ ] Push tag: `git push origin v1.2.0`
10. [ ] GitHub Actions will build and publish artifacts
11. [ ] Update documentation site
12. [ ] Announce release
```

### Automated Release Pipeline

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags:
      - 'v*'

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run tests
        run: make test-all

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build Docker images
        run: |
          docker build -t squawk:${{ github.ref_name }} .
          docker tag squawk:${{ github.ref_name }} squawk:latest

      - name: Push to registry
        run: |
          docker push squawk:${{ github.ref_name }}
          docker push squawk:latest

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Create GitHub Release
        uses: actions/create-release@v1
        with:
          tag_name: ${{ github.ref }}
          release_name: Release ${{ github.ref }}
          draft: false
          prerelease: false
```

This comprehensive development guide provides all the necessary information for developers to contribute effectively to the Squawk project, from initial setup through the release process.
