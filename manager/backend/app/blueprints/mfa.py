"""
Multi-factor authentication (TOTP) API blueprint.

Handles MFA enrollment, activation, verification, and disabling.
Endpoints require authentication except mfa-verify which uses pre-auth token.
"""

from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required, get_current_user
from app.services.auth_service import AuthService
from app.services.mfa_service import MFAService
from app.utils.decorators import validate_json, audit_log

mfa_bp = Blueprint('mfa', __name__)


@mfa_bp.route('/api/v1/mfa/enroll', methods=['POST'])
@token_required
@audit_log('mfa_enroll_started')
def enroll():
    """
    Start MFA enrollment: generate TOTP secret.

    Returns provisioning URI for QR code generation. Secret is NOT yet enabled.
    User must call activate with a valid code to enable MFA.

    Response:
        {
            "secret": "JBSWY3DPEBLW64TMMQ======",
            "provisioning_uri": "otpauth://totp/admin@Squawk...",
            "message": "Scan QR code or enter secret in authenticator app"
        }
    """
    user = get_current_user()
    db = current_app.db

    user_record = db(db.auth_user.id == user['user_id']).select().first()
    if not user_record:
        return jsonify({'error': 'User not found'}), 404

    if user_record.get('mfa_enabled'):
        return jsonify({'error': 'MFA is already enabled for this user'}), 409

    # Generate new secret (not yet stored)
    mfa_secret = MFAService.generate_totp_secret(user_record.username)

    return jsonify({
        'secret': mfa_secret.secret,
        'provisioning_uri': mfa_secret.provisioning_uri,
        'message': 'Scan QR code or enter secret in authenticator app'
    }), 200


@mfa_bp.route('/api/v1/mfa/activate', methods=['POST'])
@token_required
@validate_json('secret', 'totp_code')
@audit_log('mfa_activated')
def activate():
    """
    Activate MFA: verify TOTP code and store secret + recovery codes.

    Request:
        {
            "secret": "JBSWY3DPEBLW64TMMQ======",
            "totp_code": "123456"
        }

    Response:
        {
            "message": "MFA activated successfully",
            "recovery_codes": ["ABCD1234", "EFGH5678", ...]
        }

    Recovery codes are returned ONLY ONCE. User must store them safely.
    """
    user = get_current_user()
    data = request.get_json()

    db = current_app.db
    user_record = db.auth_user[user['user_id']]
    if not user_record:
        return jsonify({'error': 'User not found'}), 404

    if user_record.mfa_enabled:
        return jsonify({'error': 'MFA is already enabled for this user'}), 409

    secret = data['secret'].strip()
    totp_code = data['totp_code'].strip()

    # Verify the code before enabling MFA
    if not MFAService.verify_totp(secret, totp_code, window=1):
        return jsonify({'error': 'Invalid TOTP code'}), 401

    # Generate recovery codes (8 codes, returned once)
    plain_codes, hashed_codes = MFAService.generate_recovery_codes(count=8)

    # Encrypt secret and store
    encrypted_secret = MFAService.encrypt_secret(secret)
    db(db.auth_user.id == user_record['id']).update(
        mfa_enabled=True,
        mfa_secret=encrypted_secret
    )
    db.commit()

    # Store hashed recovery codes
    MFAService.store_recovery_codes(user_record['id'], hashed_codes)

    return jsonify({
        'message': 'MFA activated successfully',
        'recovery_codes': plain_codes
    }), 200


@mfa_bp.route('/api/v1/mfa/disable', methods=['POST'])
@token_required
@validate_json('password')
@audit_log('mfa_disabled')
def disable():
    """
    Disable MFA: requires password + valid TOTP code OR recovery code.

    Request (option 1 - with TOTP code):
        {
            "password": "current_password",
            "totp_code": "123456"
        }

    Request (option 2 - with recovery code):
        {
            "password": "current_password",
            "recovery_code": "ABCD1234"
        }

    Response:
        {
            "message": "MFA disabled successfully"
        }
    """
    user = get_current_user()
    data = request.get_json()

    db = current_app.db
    user_record = db(db.auth_user.id == user['user_id']).select().first()
    if not user_record:
        return jsonify({'error': 'User not found'}), 404

    if not user_record.get('mfa_enabled'):
        return jsonify({'error': 'MFA is not enabled for this user'}), 409

    password = data['password'].strip()

    # Verify password first
    if not AuthService.verify_password(password, user_record['password_hash']):
        return jsonify({'error': 'Invalid password'}), 401

    # Check for TOTP code
    totp_code = data.get('totp_code', '').strip()
    recovery_code = data.get('recovery_code', '').strip()

    if not totp_code and not recovery_code:
        return jsonify({'error': 'Must provide either totp_code or recovery_code'}), 400

    verified = False

    # Try TOTP verification
    if totp_code:
        decrypted_secret = MFAService.decrypt_secret(user_record['mfa_secret'])
        if MFAService.verify_totp(decrypted_secret, totp_code, window=1):
            verified = True

    # Try recovery code verification (single-use)
    if not verified and recovery_code:
        if MFAService.consume_recovery_code(user_record['id'], recovery_code):
            verified = True

    if not verified:
        return jsonify({'error': 'Invalid TOTP code or recovery code'}), 401

    # Disable MFA
    db(db.auth_user.id == user_record['id']).update(
        mfa_enabled=False,
        mfa_secret=None,
        mfa_recovery_codes=None,
        mfa_last_totp_counter=0
    )
    db.commit()

    return jsonify({
        'message': 'MFA disabled successfully'
    }), 200


@mfa_bp.route('/api/v1/auth/mfa-verify', methods=['POST'])
@validate_json('pre_auth_token')
def mfa_verify():
    """
    Verify MFA code and issue full JWT tokens.

    Pre-auth token is a 5-minute limited token from login that only allows
    this endpoint. Exchange it for full access + refresh tokens after
    successful TOTP/recovery code verification.

    Request:
        {
            "pre_auth_token": "...",
            "totp_code": "123456"  # OR
            "recovery_code": "ABCD1234"
        }

    Response:
        {
            "accessToken": "...",
            "refreshToken": "...",
            "user": {
                "id": 1,
                "username": "admin",
                "email": "admin@example.com",
                "global_role": "SystemAdmin"
            }
        }
    """
    data = request.get_json()
    pre_auth_token = data['pre_auth_token'].strip()

    # Validate pre-auth token
    payload = MFAService.decode_pre_auth_token(pre_auth_token)
    if not payload:
        return jsonify({'error': 'Invalid or expired pre-auth token'}), 401

    user_id = payload['user_id']
    db = current_app.db
    user_record = db(db.auth_user.id == user_id).select().first()

    if not user_record or not user_record.get('active'):
        return jsonify({'error': 'User not found or inactive'}), 404

    if not user_record.get('mfa_enabled'):
        return jsonify({'error': 'MFA not enabled for this user'}), 409

    totp_code = data.get('totp_code', '').strip()
    recovery_code = data.get('recovery_code', '').strip()

    if not totp_code and not recovery_code:
        return jsonify({'error': 'Must provide either totp_code or recovery_code'}), 400

    verified = False

    # Try TOTP verification with replay protection
    if totp_code:
        decrypted_secret = MFAService.decrypt_secret(user_record['mfa_secret'])
        if MFAService.verify_totp(decrypted_secret, totp_code, window=1):
            # Check for replay attack
            if MFAService.check_totp_replay(user_id, decrypted_secret, totp_code):
                verified = True

    # Try recovery code verification (single-use, consumes it)
    if not verified and recovery_code:
        if MFAService.consume_recovery_code(user_id, recovery_code):
            verified = True

    if not verified:
        return jsonify({'error': 'Invalid TOTP code or recovery code'}), 401

    # Fetch team roles
    team_roles = {}
    memberships = db(db.team_member.user_id == user_id).select()
    for membership in memberships:
        team_roles[membership['team_id']] = membership['role']

    # Issue full tokens
    access_token = AuthService.create_access_token(
        user_id,
        user_record['username'],
        user_record['global_role'],
        team_roles
    )
    refresh_token = AuthService.create_refresh_token(user_id)

    return jsonify({
        'accessToken': access_token,
        'refreshToken': refresh_token,
        'user': {
            'id': user_record['id'],
            'username': user_record['username'],
            'email': user_record['email'],
            'global_role': user_record['global_role'],
            'team_roles': team_roles
        }
    }), 200
