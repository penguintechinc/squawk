"""
Multi-factor authentication (TOTP) service.

Handles TOTP secret generation, verification, recovery codes, and pre-auth tokens.
Uses pyotp for TOTP generation and cryptography for secret encryption.
"""

import json
import secrets
import uuid
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass

import pyotp
import jwt
import bcrypt
from flask import current_app
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


@dataclass(slots=True)
class MFASecret:
    """TOTP secret with provisioning URI."""
    secret: str
    provisioning_uri: str


class MFAService:
    """Multi-factor authentication service for TOTP and recovery codes."""

    @staticmethod
    def _get_cipher() -> Fernet:
        """Get Fernet cipher derived from app SECRET_KEY via HKDF."""
        secret_key = current_app.config.get('SECRET_KEY', '').encode('utf-8')
        if not secret_key:
            raise ValueError('SECRET_KEY not configured')

        # Derive 32-byte key from SECRET_KEY using HKDF-SHA256
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'mfa-encryption',
            backend=default_backend()
        )
        derived_key = kdf.derive(secret_key)
        # Fernet requires base64-encoded 32-byte key
        import base64
        b64_key = base64.urlsafe_b64encode(derived_key)
        return Fernet(b64_key)

    @staticmethod
    def generate_totp_secret(username: str) -> MFASecret:
        """
        Generate a new TOTP secret and return provisioning URI.

        Args:
            username: Username for the provisioning URI

        Returns:
            MFASecret with base32 secret and otpauth:// URI for QR code
        """
        totp = pyotp.TOTP(pyotp.random_base32())
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name='Squawk DNS Manager'
        )
        return MFASecret(
            secret=totp.secret,
            provisioning_uri=provisioning_uri
        )

    @staticmethod
    def verify_totp(secret: str, code: str, window: int = 1) -> bool:
        """
        Verify a TOTP code against a secret.

        Args:
            secret: Base32-encoded TOTP secret
            code: 6-digit code from authenticator app
            window: Number of intervals to check before/after current (default 1)

        Returns:
            True if code is valid, False otherwise
        """
        if not code or len(code) != 6 or not code.isdigit():
            return False

        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=window)

    @staticmethod
    def get_totp_counter(secret: str) -> int:
        """Get the current TOTP time counter (for replay detection)."""
        totp = pyotp.TOTP(secret)
        return totp.timecode(datetime.utcnow())

    @staticmethod
    def encrypt_secret(secret: str) -> str:
        """Encrypt TOTP secret using Fernet."""
        cipher = MFAService._get_cipher()
        encrypted = cipher.encrypt(secret.encode('utf-8'))
        return encrypted.decode('utf-8')

    @staticmethod
    def decrypt_secret(encrypted_secret: str) -> str:
        """Decrypt TOTP secret using Fernet."""
        cipher = MFAService._get_cipher()
        decrypted = cipher.decrypt(encrypted_secret.encode('utf-8'))
        return decrypted.decode('utf-8')

    @staticmethod
    def hash_recovery_code(code: str) -> str:
        """Hash a recovery code using bcrypt (constant-time comparison)."""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(code.encode('utf-8'), salt).decode('utf-8')

    @staticmethod
    def verify_recovery_code(code: str, code_hash: str) -> bool:
        """Verify recovery code against hash using bcrypt constant-time comparison."""
        return bcrypt.checkpw(code.encode('utf-8'), code_hash.encode('utf-8'))

    @staticmethod
    def generate_recovery_codes(count: int = 8) -> Tuple[list[str], list[str]]:
        """
        Generate recovery codes and their hashes.

        Args:
            count: Number of codes to generate (default 8)

        Returns:
            Tuple of (plain_codes, hashed_codes)
        """
        plain_codes = []
        hashed_codes = []

        for _ in range(count):
            # Generate a 16-character hex recovery code (64 bits of entropy,
            # well above the 40-bit floor for a single-use bcrypt-hashed secret).
            code = secrets.token_hex(8).upper()
            plain_codes.append(code)
            hashed_codes.append(MFAService.hash_recovery_code(code))

        return plain_codes, hashed_codes

    @staticmethod
    def create_pre_auth_token(user_id: int) -> str:
        """
        Create a pre-auth token for MFA step-up (5-minute validity).

        Pre-auth tokens have ONLY 'mfa:verify' scope and cannot be used for
        normal API endpoints. They unlock the MFA verification endpoint only.

        Args:
            user_id: User ID requiring MFA verification

        Returns:
            Pre-auth JWT token
        """
        tenant = current_app.config.get('TENANT_ID', 'default')

        payload = {
            'sub': str(user_id),
            'iss': current_app.config['JWT_ISSUER'],
            'aud': current_app.config['JWT_AUDIENCE'],
            'tenant': tenant,
            'user_id': user_id,
            'type': 'pre_auth',
            'scope': 'mfa:verify',
            # Unique token id: lets the mfa-verify endpoint consume this
            # token on first use, capping it to a single verification
            # attempt instead of unlimited guesses within its 5-min window.
            'jti': str(uuid.uuid4()),
            'exp': datetime.utcnow() + timedelta(minutes=5),
            'iat': datetime.utcnow()
        }

        return jwt.encode(
            payload,
            current_app.config['JWT_PRIVATE_KEY'],
            algorithm=current_app.config['JWT_ALGORITHM']
        )

    @staticmethod
    def decode_pre_auth_token(token: str) -> Optional[Dict]:
        """
        Decode and validate a pre-auth token.

        Pre-auth tokens must have type='pre_auth' and scope='mfa:verify'.

        Args:
            token: Pre-auth JWT token

        Returns:
            Decoded payload if valid, None otherwise
        """
        try:
            payload = jwt.decode(
                token,
                current_app.config['JWT_PUBLIC_KEY'],
                algorithms=['ES256', 'RS256'],
                audience=current_app.config['JWT_AUDIENCE'],
                issuer=current_app.config['JWT_ISSUER'],
                options={'require': ['exp', 'iat', 'tenant', 'type', 'scope']}
            )

            # Verify token type and scope
            if payload.get('type') != 'pre_auth' or payload.get('scope') != 'mfa:verify':
                return None

            if not payload.get('tenant'):
                return None

            return payload

        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return None

    @staticmethod
    def store_recovery_codes(user_id: int, hashed_codes: list[str]) -> None:
        """Store recovery codes as JSON array in database."""
        db = current_app.db
        db(db.auth_user.id == user_id).update(mfa_recovery_codes=json.dumps(hashed_codes))
        db.commit()

    @staticmethod
    def get_recovery_codes(user_id: int) -> list[str]:
        """Get stored recovery code hashes as list."""
        db = current_app.db
        user = db.auth_user[user_id]
        if user and user.mfa_recovery_codes:
            return json.loads(user.mfa_recovery_codes)
        return []

    @staticmethod
    def consume_recovery_code(user_id: int, code: str) -> bool:
        """
        Verify recovery code and remove it from the list (single-use).

        Args:
            user_id: User ID
            code: Plain recovery code

        Returns:
            True if code was valid and consumed, False otherwise
        """
        db = current_app.db
        user = db(db.auth_user.id == user_id).select().first()
        if not user:
            return False

        stored_hashes = MFAService.get_recovery_codes(user_id)
        if not stored_hashes:
            return False

        # Find and verify the code
        for i, code_hash in enumerate(stored_hashes):
            if MFAService.verify_recovery_code(code, code_hash):
                # Remove the used code
                stored_hashes.pop(i)
                db(db.auth_user.id == user_id).update(mfa_recovery_codes=json.dumps(stored_hashes))
                db.commit()
                return True

        return False

    @staticmethod
    def check_totp_replay(user_id: int, secret: str, code: str) -> bool:
        """
        Check if TOTP code represents a new timestamp (replay prevention).

        Stores the last-used time counter per user. Reuse of the same code
        within the same time window is rejected.

        Args:
            user_id: User ID
            secret: Decrypted TOTP secret
            code: TOTP code to verify

        Returns:
            True if code is from a new time counter, False if replay detected
        """
        db = current_app.db
        user = db(db.auth_user.id == user_id).select().first()
        if not user:
            return False

        current_counter = MFAService.get_totp_counter(secret)
        last_counter = user.get('mfa_last_totp_counter') or 0

        # If counter hasn't advanced, this is a replay
        if current_counter <= last_counter:
            return False

        # Update the last-used counter
        db(db.auth_user.id == user_id).update(mfa_last_totp_counter=current_counter)
        db.commit()
        return True
