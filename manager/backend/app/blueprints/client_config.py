"""
Client Configuration API blueprint.
Handles client configuration management and retrieval.
"""

import os
from functools import wraps
from typing import Optional
from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required
from app.utils.responses import internal_error

client_config_bp = Blueprint('client_config', __name__)


def _get_deployment_id() -> str:
    """Get stable deployment identifier for PostHog flag checks."""
    return os.getenv('HOSTNAME', 'squawk-manager')


def _check_client_config_flag():
    """
    Decorator to enforce PostHog flag gating for client config operations.

    PostHog flag 'squawkdns.client-config' must be enabled.
    Returns 403 if flag disabled.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            posthog = current_app.posthog
            distinct_id = _get_deployment_id()
            flag_enabled = posthog.feature_enabled(
                'squawkdns.client-config',
                distinct_id,
                default=False,
            )

            if not flag_enabled:
                return jsonify({
                    'error': 'Client configuration feature is disabled',
                    'feature_flag': 'squawkdns.client-config',
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator


@client_config_bp.route('/api/v1/client-config/domains', methods=['POST'])
@token_required
@_check_client_config_flag()
def create_domain():
    """
    Create a new deployment domain.

    Request body:
        {
            "name": "domain-name",
            "description": "Domain description"
        }

    Response:
        {
            "success": true,
            "id": 1,
            "name": "domain-name",
            "jwt_token": "eyJ..."
        }

    Status codes:
        201: Domain created
        400: Invalid request
        403: Feature disabled
        500: Internal error
    """
    try:
        client_config_mgr = current_app.client_config_manager
        data = request.get_json()

        if not data or 'name' not in data:
            return jsonify({'error': 'Missing required field: name'}), 400

        name = data.get('name')
        description = data.get('description', '')

        result = client_config_mgr.create_deployment_domain(
            name=name,
            description=description,
            created_by=request.headers.get('X-User-ID', 'unknown'),
        )

        if result.get('success'):
            return jsonify(result), 201
        else:
            return jsonify(result), 400

    except Exception as e:
        return internal_error(e)


@client_config_bp.route('/api/v1/client-config/domains/<int:domain_id>/jwt-rollover',
                         methods=['POST'])
@token_required
@_check_client_config_flag()
def rollover_jwt(domain_id: int):
    """
    Rollover JWT token for a deployment domain.

    Response:
        {
            "success": true,
            "new_jwt": "eyJ...",
            "expires_at": "2026-07-08T..."
        }

    Status codes:
        200: JWT rolled over
        403: Feature disabled
        404: Domain not found
        500: Internal error
    """
    try:
        client_config_mgr = current_app.client_config_manager
        result = client_config_mgr.rollover_domain_jwt(
            domain_id=domain_id,
            admin_user=request.headers.get('X-User-ID', 'unknown'),
        )

        if result.get('success'):
            return jsonify(result), 200
        else:
            return jsonify(result), 404

    except Exception as e:
        return internal_error(e)


@client_config_bp.route('/api/v1/client-config/domains/<int:domain_id>/configs',
                         methods=['POST'])
@token_required
@_check_client_config_flag()
def create_config(domain_id: int):
    """
    Create a new client configuration for a domain.

    Request body:
        {
            "name": "config-name",
            "description": "Config description",
            "config_data": {
                "server_url": "https://dns.example.com",
                "dns_port": 53,
                "cache_enabled": true,
                ...
            }
        }

    Response:
        {
            "success": true,
            "config_id": 1,
            "version": 1
        }

    Status codes:
        201: Config created
        400: Invalid config
        403: Feature disabled
        500: Internal error
    """
    try:
        client_config_mgr = current_app.client_config_manager
        data = request.get_json()

        if not data or 'name' not in data or 'config_data' not in data:
            return jsonify({'error': 'Missing required fields: name, config_data'}), 400

        name = data.get('name')
        config_data = data.get('config_data')
        description = data.get('description', '')

        result = client_config_mgr.create_client_config(
            name=name,
            domain_id=domain_id,
            config_data=config_data,
            description=description,
            created_by=request.headers.get('X-User-ID', 'unknown'),
        )

        if result.get('success'):
            return jsonify(result), 201
        else:
            return jsonify(result), 400

    except Exception as e:
        return internal_error(e)


@client_config_bp.route('/api/v1/client-config/configs/<int:config_id>',
                         methods=['PUT'])
@token_required
@_check_client_config_flag()
def update_config(config_id: int):
    """
    Update an existing client configuration.

    Request body:
        {
            "config_data": {...},
            "description": "Update description"
        }

    Response:
        {
            "success": true,
            "version": 2
        }

    Status codes:
        200: Config updated
        400: Invalid config
        403: Feature disabled
        404: Config not found
        500: Internal error
    """
    try:
        client_config_mgr = current_app.client_config_manager
        data = request.get_json()

        if not data or 'config_data' not in data:
            return jsonify({'error': 'Missing required field: config_data'}), 400

        config_data = data.get('config_data')
        description = data.get('description', '')

        result = client_config_mgr.update_client_config(
            config_id=config_id,
            config_data=config_data,
            description=description,
            changed_by=request.headers.get('X-User-ID', 'unknown'),
        )

        if result.get('success'):
            return jsonify(result), 200
        else:
            return jsonify(result), 400

    except Exception as e:
        return internal_error(e)


@client_config_bp.route('/api/v1/client-config/register', methods=['POST'])
@_check_client_config_flag()
def register_client():
    """
    Register a client instance with a deployment domain.

    Request body:
        {
            "client_id": "client-123",
            "domain_jwt": "eyJ...",
            "hostname": "client-hostname",
            "ip_address": "192.168.1.100",
            "client_version": "v2.0.0",
            "os_info": "Linux Ubuntu 22.04"
        }

    Response:
        {
            "success": true,
            "client_record_id": 1,
            "domain_name": "test-domain"
        }

    Status codes:
        201: Client registered
        400: Invalid request
        403: Feature disabled
        500: Internal error
    """
    try:
        client_config_mgr = current_app.client_config_manager
        data = request.get_json()

        if not data or not all(k in data for k in ['client_id', 'domain_jwt', 'hostname', 'ip_address']):
            return jsonify({'error': 'Missing required fields'}), 400

        result = client_config_mgr.register_client(
            client_id=data.get('client_id'),
            domain_jwt=data.get('domain_jwt'),
            hostname=data.get('hostname'),
            ip_address=data.get('ip_address'),
            client_version=data.get('client_version', ''),
            os_info=data.get('os_info', ''),
            user_token=data.get('user_token'),
        )

        if result.get('success'):
            return jsonify(result), 201
        else:
            return jsonify(result), 400

    except Exception as e:
        return internal_error(e)


@client_config_bp.route('/api/v1/client-config/pull', methods=['POST'])
@_check_client_config_flag()
def pull_config():
    """
    Pull client configuration.

    Request body:
        {
            "client_id": "client-123",
            "domain_jwt": "eyJ...",
            "user_token": "optional-user-token"
        }

    Response:
        {
            "success": true,
            "config": {...},
            "version": 1,
            "config_name": "default",
            "last_updated": "2026-07-08T..."
        }

    Status codes:
        200: Config retrieved
        400: Invalid request
        403: Feature disabled
        404: Client/config not found
        500: Internal error
    """
    try:
        client_config_mgr = current_app.client_config_manager
        data = request.get_json()

        if not data or not all(k in data for k in ['client_id', 'domain_jwt']):
            return jsonify({'error': 'Missing required fields: client_id, domain_jwt'}), 400

        result = client_config_mgr.pull_client_config(
            client_id=data.get('client_id'),
            domain_jwt=data.get('domain_jwt'),
            user_token=data.get('user_token'),
        )

        if result.get('success'):
            return jsonify(result), 200
        else:
            return jsonify(result), 404

    except Exception as e:
        return internal_error(e)


@client_config_bp.route('/api/v1/client-config/assign', methods=['POST'])
@token_required
@_check_client_config_flag()
def assign_config():
    """
    Assign a specific configuration to a client.

    Request body:
        {
            "client_id": "client-123",
            "config_id": 1
        }

    Response:
        {
            "success": true
        }

    Status codes:
        200: Config assigned
        400: Invalid request
        403: Feature disabled
        404: Client/config not found
        500: Internal error
    """
    try:
        client_config_mgr = current_app.client_config_manager
        data = request.get_json()

        if not data or not all(k in data for k in ['client_id', 'config_id']):
            return jsonify({'error': 'Missing required fields: client_id, config_id'}), 400

        result = client_config_mgr.assign_config_to_client(
            client_id=data.get('client_id'),
            config_id=data.get('config_id'),
            assigned_by=request.headers.get('X-User-ID', 'unknown'),
        )

        if result.get('success'):
            return jsonify(result), 200
        else:
            return jsonify(result), 404

    except Exception as e:
        return internal_error(e)


@client_config_bp.route('/api/v1/client-config/domains/<int:domain_id>/clients',
                         methods=['GET'])
@token_required
@_check_client_config_flag()
def get_domain_clients(domain_id: int):
    """
    Get all clients in a deployment domain.

    Response:
        {
            "clients": [
                {
                    "client_id": "client-123",
                    "hostname": "hostname",
                    "ip_address": "192.168.1.100",
                    ...
                }
            ]
        }

    Status codes:
        200: Clients retrieved
        403: Feature disabled
        500: Internal error
    """
    try:
        client_config_mgr = current_app.client_config_manager
        clients = client_config_mgr.get_domain_clients(domain_id)
        return jsonify({'clients': clients}), 200
    except Exception as e:
        return internal_error(e)


@client_config_bp.route('/api/v1/client-config/stats', methods=['GET'])
@token_required
@_check_client_config_flag()
def get_stats():
    """
    Get client configuration statistics.

    Response:
        {
            "domains": {"total": 5, "active": 5},
            "clients": {"total": 20, "active": 18, ...},
            "configurations": {"total": 10, "active": 10},
            "timestamp": "2026-07-08T..."
        }

    Status codes:
        200: Stats retrieved
        403: Feature disabled
        500: Internal error
    """
    try:
        client_config_mgr = current_app.client_config_manager
        stats = client_config_mgr.get_client_stats()
        return jsonify(stats), 200
    except Exception as e:
        return internal_error(e)
