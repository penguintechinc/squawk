"""
User Model Unit Tests
Tests user authentication and model logic
"""

import pytest
from unittest.mock import MagicMock
from werkzeug.security import generate_password_hash, check_password_hash


class User:
    """User class for Flask-Login (copied from auth blueprint for testing)"""

    def __init__(self, user_row):
        self.id = user_row.id
        self.email = user_row.email
        self.first_name = user_row.first_name
        self.last_name = user_row.last_name
        self.is_admin = user_row.is_admin
        self._is_active = user_row.is_active

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return self._is_active

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)


@pytest.mark.unit
@pytest.mark.model
class TestUserModel:
    """Test User model properties"""

    def test_user_is_authenticated(self, mock_user):
        """User is always authenticated"""
        user_row = mock_user
        user = User(user_row)

        assert user.is_authenticated is True

    def test_user_is_not_anonymous(self, mock_user):
        """User is not anonymous"""
        user_row = mock_user
        user = User(user_row)

        assert user.is_anonymous is False

    def test_user_is_active(self, mock_user):
        """User active status reflects database"""
        mock_user.is_active = True
        user = User(mock_user)
        assert user.is_active is True

        mock_user.is_active = False
        user = User(mock_user)
        assert user.is_active is False

    def test_get_id_returns_string(self, mock_user):
        """get_id returns string representation"""
        mock_user.id = 123
        user = User(mock_user)

        assert user.get_id() == "123"
        assert isinstance(user.get_id(), str)

    def test_user_admin_status(self, mock_user, mock_admin_user):
        """Admin status is correctly set"""
        regular_user = User(mock_user)
        admin_user = User(mock_admin_user)

        assert regular_user.is_admin is False
        assert admin_user.is_admin is True


@pytest.mark.unit
@pytest.mark.model
class TestPasswordHashing:
    """Test password hashing and verification"""

    def test_password_hash_is_generated(self):
        """Password hash is generated correctly"""
        password = "TestPassword123!"
        hashed = generate_password_hash(password)

        assert hashed != password
        assert len(hashed) > 0

    def test_password_verification_succeeds(self):
        """Correct password verifies successfully"""
        password = "TestPassword123!"
        hashed = generate_password_hash(password)

        assert check_password_hash(hashed, password) is True

    def test_password_verification_fails_wrong_password(self):
        """Wrong password fails verification"""
        password = "TestPassword123!"
        hashed = generate_password_hash(password)

        assert check_password_hash(hashed, "WrongPassword") is False

    def test_different_passwords_have_different_hashes(self):
        """Different passwords produce different hashes"""
        hash1 = generate_password_hash("Password1")
        hash2 = generate_password_hash("Password2")

        assert hash1 != hash2

    def test_same_password_different_hashes(self):
        """Same password can produce different hashes (salted)"""
        password = "TestPassword123!"
        hash1 = generate_password_hash(password)
        hash2 = generate_password_hash(password)

        # Hashes should be different due to salting
        assert hash1 != hash2

        # But both should verify correctly
        assert check_password_hash(hash1, password) is True
        assert check_password_hash(hash2, password) is True


@pytest.mark.unit
@pytest.mark.model
class TestPasswordComplexity:
    """Test password complexity validation"""

    def validate_password_complexity(self, password):
        """Validate password meets complexity requirements"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if not any(c.isupper() for c in password):
            return False, "Password must contain uppercase letter"
        if not any(c.islower() for c in password):
            return False, "Password must contain lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain digit"
        return True, "Password is valid"

    def test_valid_complex_password(self):
        """Complex password passes validation"""
        valid, _ = self.validate_password_complexity("ValidPass123")
        assert valid is True

    def test_password_too_short(self):
        """Short password fails validation"""
        valid, message = self.validate_password_complexity("Short1")
        assert valid is False
        assert "8 characters" in message

    def test_password_no_uppercase(self):
        """Password without uppercase fails"""
        valid, message = self.validate_password_complexity("lowercase123")
        assert valid is False
        assert "uppercase" in message

    def test_password_no_lowercase(self):
        """Password without lowercase fails"""
        valid, message = self.validate_password_complexity("UPPERCASE123")
        assert valid is False
        assert "lowercase" in message

    def test_password_no_digit(self):
        """Password without digit fails"""
        valid, message = self.validate_password_complexity("NoDigitsHere")
        assert valid is False
        assert "digit" in message


@pytest.mark.unit
@pytest.mark.model
class TestUserRoles:
    """Test user role management"""

    def test_regular_user_not_admin(self, mock_user):
        """Regular user is not admin"""
        mock_user.is_admin = False
        user = User(mock_user)

        assert user.is_admin is False

    def test_admin_user_is_admin(self, mock_admin_user):
        """Admin user is admin"""
        user = User(mock_admin_user)

        assert user.is_admin is True

    def test_user_attributes_from_row(self, mock_user):
        """User attributes are copied from database row"""
        mock_user.id = 42
        mock_user.email = "test@test.com"
        mock_user.first_name = "John"
        mock_user.last_name = "Doe"

        user = User(mock_user)

        assert user.id == 42
        assert user.email == "test@test.com"
        assert user.first_name == "John"
        assert user.last_name == "Doe"
