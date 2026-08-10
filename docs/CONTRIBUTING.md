# Contributing to Squawk

We welcome contributions to Squawk! This document provides guidelines for contributing to the project.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Contributing Process](#contributing-process)
5. [Coding Standards](#coding-standards)
6. [Testing Guidelines](#testing-guidelines)
7. [Documentation](#documentation)
8. [Security Guidelines](#security-guidelines)
9. [Issue Reporting](#issue-reporting)
10. [Pull Request Process](#pull-request-process)

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- **Be respectful**: Treat all contributors with respect and kindness
- **Be inclusive**: Welcome newcomers and help them succeed
- **Be collaborative**: Work together constructively
- **Be professional**: Keep discussions focused and constructive
- **Be responsible**: Take responsibility for your contributions

## Requirements to Collaborate

This is a Penguin Technologies Group LLC project, released under the AGPL-3.0 license. All contributors must:

1. **Accept the License**: All contributions are subject to AGPL-3.0 terms
2. **Sign the CLA**: Contributor License Agreement required for code contributions
3. **Follow Security Guidelines**: Adhere to security best practices for DNS infrastructure
4. **Maintain Quality**: Ensure contributions meet our quality standards

### Contributor License Agreement (CLA)

Before your first contribution, you must sign our CLA:

> **Example:** Replace `your-email@example.com` and `Your Name` with your actual email address and name.
```bash
# Sign the CLA electronically
curl -X POST https://cla.penguintech.group/sign \
  -d "project=squawk&email=your-email@example.com&name=Your Name"
```

Or visit: https://cla.penguintech.group/squawk

## Getting Started

### Prerequisites

- Python 3.8+
- Git
- Docker (optional, for testing)
- Basic understanding of DNS protocols
- Familiarity with HTTP/HTTPS

### First-time Setup

```bash
# Clone the repository
git clone https://github.com/penguintechinc/squawk.git
cd Squawk

# Create development branch
git checkout -b feature/your-feature-name

# Set up development environment
cd dns-server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests to ensure everything works
python -m pytest tests/
```

## Development Setup

### Environment Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Set up database for testing
export TEST_DB_URL="sqlite:///test.db"

# Start development services
./start_console.sh
```

### Development Dependencies

```txt
# requirements-dev.txt
pytest>=7.0.0
pytest-cov>=4.0.0
ruff>=0.8.4
mypy>=0.991
pre-commit>=2.20.0
pytest-mock>=3.8.0
httpx>=0.23.0
factory-boy>=3.2.0
```

### Code Formatting

We use several tools for code quality (ruff supersedes flake8/black/isort — see `pyproject.toml` `[tool.ruff]`):

```bash
# Format code with ruff
ruff format dns-server/app dns-server/tests

# Lint with ruff
ruff check dns-server/app --select=F,E9,B

# Type checking with mypy
mypy dns-server/bins/server.py
```

## Contributing Process

### 1. Fork and Clone

```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR_USERNAME/Squawk.git
cd Squawk

# Add upstream remote
git remote add upstream https://github.com/penguintechinc/squawk.git
```

### 2. Create Feature Branch

```bash
# Create and switch to feature branch
git checkout -b feature/your-feature-name

# Keep your branch up to date
git fetch upstream
git rebase upstream/main
```

### 3. Make Changes

- Follow our coding standards
- Write tests for new features
- Update documentation as needed
- Commit regularly with clear messages

### 4. Test Your Changes

```bash
# Run all tests
python -m pytest

# Run specific test categories
python -m pytest tests/unit/
python -m pytest tests/integration/
python -m pytest tests/security/

# Check code coverage
python -m pytest --cov=dns_server --cov=dns_client

# Test with different Python versions (if available)
tox
```

### 5. Submit Pull Request

```bash
# Push your changes
git push origin feature/your-feature-name

# Create pull request on GitHub
# Include description of changes and link to issues
```

## Coding Standards

### Python Style Guide

We follow PEP 8 with some modifications:

```python
# Line length: 88 characters (black default)
# Use double quotes for strings
# Use type hints where possible
# Document all public functions and classes

def process_dns_query(domain: str, record_type: str = "A") -> Dict[str, Any]:
    """Process a DNS query for the given domain and record type.

    Args:
        domain: The domain name to query
        record_type: The DNS record type (default: A)

    Returns:
        Dictionary containing the DNS response

    Raises:
        ValueError: If domain is invalid
        DNSException: If query fails
    """
    pass
```

### Directory Structure

```
Squawk/
├── dns-server/           # Server component
│   ├── bins/            # Executable scripts
│   │   └── server.py    # Main server script
│   ├── libs/            # Shared libraries
│   ├── tests/           # Server tests
│   ├── web/             # Py4web applications
│   │   └── apps/        # Web applications
│   └── venv/            # Virtual environment
├── dns-client/          # Client component
│   ├── bins/            # Client executables
│   ├── libs/            # Client libraries
│   └── tests/           # Client tests
├── docs/                # Documentation
├── docker/              # Docker configurations
└── scripts/             # Build and deployment scripts
```

### Naming Conventions

```python
# Variables and functions: snake_case
def validate_token(token_value: str) -> bool:
    is_valid = check_database(token_value)
    return is_valid

# Classes: PascalCase
class DNSQueryHandler:
    pass

# Constants: UPPER_SNAKE_CASE
DEFAULT_PORT = 8080
MAX_QUERY_TIMEOUT = 30

# Private methods: _leading_underscore
def _internal_helper(self) -> None:
    pass
```

## Testing Guidelines

### Test Structure

```
tests/
├── unit/              # Unit tests
│   ├── test_server.py
│   ├── test_client.py
│   └── test_auth.py
├── integration/       # Integration tests
│   ├── test_end_to_end.py
│   └── test_database.py
├── security/          # Security tests
│   ├── test_auth_bypass.py
│   └── test_injection.py
├── performance/       # Performance tests
│   └── test_load.py
├── fixtures/          # Test data
└── conftest.py        # Pytest configuration
```

### Writing Tests

```python
# test_server.py
import pytest
from unittest.mock import Mock, patch
from dns_server.server import DNSHandler

class TestDNSHandler:
    def test_valid_token_allows_query(self):
        """Test that valid token allows DNS query."""
        handler = DNSHandler()
        handler.headers = {"Authorization": "Bearer valid-token"}

        with patch.object(handler, 'check_token_permission_new') as mock_check:
            mock_check.return_value = True
            result = handler.do_GET()

        mock_check.assert_called_once()
        assert result is not None

    def test_invalid_token_denies_query(self):
        """Test that invalid token denies DNS query."""
        handler = DNSHandler()
        handler.headers = {"Authorization": "Bearer invalid-token"}

        with patch.object(handler, 'send_response') as mock_response:
            handler.do_GET()

        mock_response.assert_called_with(403)

    @pytest.mark.parametrize("domain,expected", [
        ("example.com", True),
        ("test.example.com", True),
        ("invalid..domain", False),
        ("", False),
    ])
    def test_domain_validation(self, domain, expected):
        """Test domain validation logic."""
        handler = DNSHandler()
        result = handler.is_valid_domain(domain)
        assert result == expected
```

### Test Categories

1. **Unit Tests**: Test individual functions/methods
2. **Integration Tests**: Test component interactions
3. **Security Tests**: Test security vulnerabilities
4. **Performance Tests**: Test performance characteristics
5. **End-to-End Tests**: Test complete workflows

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=dns_server --cov-report=html

# Run specific test file
pytest tests/unit/test_server.py

# Run tests matching pattern
pytest -k "test_token"

# Run tests with verbose output
pytest -v

# Run tests in parallel
pytest -n auto
```

## Documentation

### Code Documentation

```python
def authenticate_token(token: str, domain: str) -> bool:
    """Authenticate token for domain access.

    This function checks if the provided token has permission to access
    the specified domain. It supports both exact domain matches and
    wildcard permissions.

    Args:
        token: The authentication token to validate
        domain: The domain name being accessed

    Returns:
        True if token has permission, False otherwise

    Raises:
        DatabaseError: If database connection fails
        ValidationError: If inputs are invalid

    Example:
        >>> authenticate_token("abc123", "example.com")
        True
        >>> authenticate_token("invalid", "example.com")
        False
    """
    pass
```

### API Documentation

Document all API endpoints:

```python
@action('api/tokens', method=['POST'])
@action.uses(db)
def api_create_token():
    """Create a new authentication token.

    POST /dns_console/api/tokens

    Request Body:
        {
            "name": "Token name",
            "description": "Token description",
            "domains": ["example.com", "*.test.com"]
        }

    Response:
        {
            "success": true,
            "token": "generated-token-value",
            "id": 123
        }

    Error Responses:
        400: Invalid request data
        409: Token name already exists
        500: Internal server error
    """
    pass
```

### README Updates

When adding features, update:
- Feature list in README.md
- Installation instructions if needed
- Configuration examples
- Usage examples

## Security Guidelines

### Security-First Development

1. **Input Validation**: Validate all user inputs
2. **SQL Injection Prevention**: Use parameterized queries
3. **Authentication**: Secure token generation and validation
4. **Authorization**: Proper permission checking
5. **Logging**: Log security events without exposing sensitive data

### Security Testing

```python
def test_sql_injection_prevention():
    """Test that SQL injection attempts are blocked."""
    malicious_token = "'; DROP TABLE tokens; --"
    result = authenticate_token(malicious_token, "example.com")
    assert result is False

def test_token_enumeration_protection():
    """Test that token enumeration is not possible."""
    # Test that invalid tokens don't reveal information
    pass

def test_domain_bypass_attempts():
    """Test various domain bypass techniques."""
    bypass_attempts = [
        "../admin.com",
        "admin.com/../example.com",
        "example.com\x00admin.com"
    ]
    for attempt in bypass_attempts:
        assert not is_valid_domain(attempt)
```

### Responsible Disclosure

If you find security vulnerabilities:

1. **Do not** create public issues
2. Email security@penguintech.group
3. Include detailed reproduction steps
4. Allow 90 days for fix before disclosure
5. We'll acknowledge within 24 hours

## Issue Reporting

### Before Creating Issues

1. Check existing issues for duplicates
2. Test with latest version
3. Gather debugging information
4. Try minimal reproduction case

### Issue Template

```markdown
## Issue Description
Brief description of the problem

## Environment
- Squawk Version: 1.x.x
- Python Version: 3.x.x
- Operating System: Linux/Windows/macOS
- Deployment Method: Docker/Manual/Kubernetes

## Reproduction Steps
1. Step one
2. Step two
3. Step three

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Additional Context
- Logs
- Configuration files
- Screenshots
```

### Issue Labels

- `bug`: Something isn't working
- `enhancement`: New feature request
- `documentation`: Documentation updates
- `security`: Security-related issues
- `performance`: Performance improvements
- `good-first-issue`: Good for new contributors
- `help-wanted`: Extra attention needed

## Pull Request Process

### PR Requirements

Before submitting:

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Security considerations addressed
- [ ] Breaking changes documented
- [ ] Issue linked (if applicable)

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## Security Considerations
- [ ] No sensitive data exposed
- [ ] Input validation implemented
- [ ] Authorization checks added

## Documentation
- [ ] README updated
- [ ] API docs updated
- [ ] Code comments added

## Related Issues
Fixes #123
```

### Review Process

1. **Automated Checks**: CI/CD pipeline runs tests
2. **Code Review**: Maintainers review code quality
3. **Security Review**: Security team reviews sensitive changes
4. **Documentation Review**: Docs team reviews documentation
5. **Final Approval**: Project maintainers approve merge

### Getting Your PR Reviewed

- Keep PRs focused and small
- Write clear commit messages
- Respond to feedback promptly
- Update PR based on reviews
- Be patient - reviews take time

## Release Process

### Version Numbering

We use Semantic Versioning (semver):

- `MAJOR.MINOR.PATCH`
- Major: Breaking changes
- Minor: New features (backward compatible)
- Patch: Bug fixes (backward compatible)

### Release Timeline

- **Major releases**: Quarterly
- **Minor releases**: Monthly
- **Patch releases**: As needed
- **Security patches**: Immediately

## Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and ideas
- **Discord**: Real-time chat (invite link in README)
- **Email**: security@penguintech.group for security issues

### Documentation Resources

- **README.md**: Project overview and quick start
- **docs/USAGE.md**: Detailed usage guide
- **docs/API.md**: API reference
- **docs/ARCHITECTURE.md**: Technical architecture
- **Wiki**: Additional guides and tutorials

### Contributor Resources

- **Good First Issues**: Issues labeled `good-first-issue`
- **Mentorship Program**: Pair new contributors with mentors
- **Office Hours**: Weekly video calls with maintainers
- **Contributor Guide**: This document

## Recognition

### Contributor Recognition

We recognize contributions in several ways:

- **Contributors file**: Listed in CONTRIBUTORS.md
- **Release notes**: Major contributions highlighted
- **Hall of Fame**: Top contributors featured
- **Swag**: Stickers and t-shirts for regular contributors

### Maintainer Path

Regular contributors may be invited to become maintainers:

1. **Active contributor** for 6+ months
2. **High-quality contributions**
3. **Community involvement**
4. **Technical expertise**
5. **Alignment with project values**

Maintainers have additional responsibilities:
- Code review
- Issue triage
- Release management
- Community support

## License and Legal

### License Agreement

All contributions are licensed under AGPL-3.0. By contributing:

- You grant PenguinTech Group LLC a perpetual license
- You retain copyright to your contributions
- Your code must be compatible with AGPL-3.0
- You confirm you have rights to contribute

### Copyright Notice

Include copyright notice in new files:

```python
# Copyright (c) 2024 Penguin Technologies Group LLC
#
# This file is part of Squawk.
#
# Squawk is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
```

Thank you for contributing to Squawk! Together we can build better DNS infrastructure for everyone.
