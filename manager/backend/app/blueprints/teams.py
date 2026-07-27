"""
Team management API blueprint.
Handles team CRUD and member management.
"""

from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required
from app.middleware.rbac import requires_scope, requires_team_role, can_access_team, filter_teams_by_access
from app.utils.decorators import validate_json, audit_log
from app.utils.validators import validate_team_role

teams_bp = Blueprint('teams', __name__)


@teams_bp.route('/api/v1/teams', methods=['GET'])
@token_required
def list_teams():
    """
    List teams accessible to current user.

    Response:
        [
            {
                "id": 1,
                "name": "Engineering",
                "description": "Engineering team",
                "created_at": "2024-01-01T00:00:00",
                "member_count": 5
            }
        ]
    """
    db = current_app.db

    # Get accessible team IDs
    accessible_team_ids = filter_teams_by_access()

    if not accessible_team_ids:
        return jsonify([]), 200

    teams = db(db.team.id.belongs(accessible_team_ids)).select(
        db.team.ALL,
        orderby=db.team.name
    )

    result = []
    for team in teams:
        member_count = db(db.team_member.team_id == team.id).count()
        result.append({
            'id': team.id,
            'name': team.name,
            'description': team.description,
            'created_at': team.created_at.isoformat(),
            'member_count': member_count
        })

    return jsonify(result), 200


@teams_bp.route('/api/v1/teams', methods=['POST'])
@token_required
@requires_scope('teams:write')
@validate_json('name')
@audit_log('team_created')
def create_team():
    """
    Create a new team.

    Request:
        {
            "name": "Engineering",
            "description": "Engineering team"
        }

    Response:
        {
            "id": 1,
            "name": "Engineering",
            "description": "Engineering team"
        }
    """
    data = request.get_json()
    db = current_app.db

    # Check if team name already exists
    if db(db.team.name == data['name']).count() > 0:
        return jsonify({'error': 'Team name already exists'}), 409

    # Create team
    team_id = db.team.insert(
        name=data['name'],
        description=data.get('description', '')
    )

    db.commit()

    team = db.team[team_id]

    return jsonify({
        'id': team.id,
        'name': team.name,
        'description': team.description,
        'created_at': team.created_at.isoformat()
    }), 201


@teams_bp.route('/api/v1/teams/<int:team_id>', methods=['GET'])
@token_required
def get_team(team_id):
    """Get team details."""
    if not can_access_team(team_id):
        return jsonify({'error': 'Access denied'}), 403

    db = current_app.db
    team = db.team[team_id]

    if not team:
        return jsonify({'error': 'Team not found'}), 404

    member_count = db(db.team_member.team_id == team_id).count()

    return jsonify({
        'id': team.id,
        'name': team.name,
        'description': team.description,
        'member_count': member_count,
        'created_at': team.created_at.isoformat()
    }), 200


@teams_bp.route('/api/v1/teams/<int:team_id>', methods=['PUT'])
@token_required
@requires_team_role('team_id', 'TeamAdmin')
@audit_log('team_updated')
def update_team(team_id):
    """
    Update team information.

    Request:
        {
            "name": "New Name",
            "description": "New description"
        }
    """
    db = current_app.db
    team = db.team[team_id]

    if not team:
        return jsonify({'error': 'Team not found'}), 404

    data = request.get_json()

    if 'name' in data:
        # Check if new name conflicts
        existing = db((db.team.name == data['name']) & (db.team.id != team_id)).count()
        if existing > 0:
            return jsonify({'error': 'Team name already exists'}), 409
        team.update_record(name=data['name'])

    if 'description' in data:
        team.update_record(description=data['description'])

    db.commit()

    return jsonify({
        'id': team.id,
        'name': team.name,
        'description': team.description
    }), 200


@teams_bp.route('/api/v1/teams/<int:team_id>', methods=['DELETE'])
@token_required
@requires_scope('teams:write')
@audit_log('team_deleted')
def delete_team(team_id):
    """Delete team and all memberships."""
    db = current_app.db
    team = db.team[team_id]

    if not team:
        return jsonify({'error': 'Team not found'}), 404

    # Delete team (cascade will delete memberships)
    del db.team[team_id]
    db.commit()

    return jsonify({
        'message': 'Team deleted successfully'
    }), 200


@teams_bp.route('/api/v1/teams/<int:team_id>/members', methods=['GET'])
@token_required
def list_team_members(team_id):
    """List team members."""
    if not can_access_team(team_id):
        return jsonify({'error': 'Access denied'}), 403

    db = current_app.db

    members = db(db.team_member.team_id == team_id).select(
        db.team_member.ALL,
        db.auth_user.ALL,
        left=db.auth_user.on(db.team_member.user_id == db.auth_user.id),
        orderby=db.auth_user.username
    )

    return jsonify([
        {
            'user_id': m.team_member.user_id,
            'username': m.auth_user.username,
            'email': m.auth_user.email,
            'role': m.team_member.role,
            'joined_at': m.team_member.joined_at.isoformat()
        }
        for m in members
    ]), 200


@teams_bp.route('/api/v1/teams/<int:team_id>/members', methods=['POST'])
@token_required
@requires_team_role('team_id', 'TeamAdmin')
@validate_json('user_id', 'role')
@audit_log('team_member_added')
def add_team_member(team_id):
    """
    Add member to team.

    Request:
        {
            "user_id": 2,
            "role": "TeamMember"
        }
    """
    data = request.get_json()
    db = current_app.db

    # Validate role
    if not validate_team_role(data['role']):
        return jsonify({'error': 'Invalid team role'}), 400

    # Check if user exists
    user = db.auth_user[data['user_id']]
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Check if already member
    existing = db(
        (db.team_member.team_id == team_id) &
        (db.team_member.user_id == data['user_id'])
    ).count()

    if existing > 0:
        return jsonify({'error': 'User is already a team member'}), 409

    # Add member
    db.team_member.insert(
        team_id=team_id,
        user_id=data['user_id'],
        role=data['role']
    )

    db.commit()

    return jsonify({
        'message': 'Team member added successfully',
        'user_id': data['user_id'],
        'role': data['role']
    }), 201


@teams_bp.route('/api/v1/teams/<int:team_id>/members/<int:user_id>', methods=['PUT'])
@token_required
@requires_team_role('team_id', 'TeamAdmin')
@audit_log('team_member_role_updated')
def update_team_member_role(team_id, user_id):
    """
    Update team member role.

    Request:
        {
            "role": "TeamAdmin"
        }
    """
    data = request.get_json()
    db = current_app.db

    if 'role' not in data:
        return jsonify({'error': 'Role is required'}), 400

    if not validate_team_role(data['role']):
        return jsonify({'error': 'Invalid team role'}), 400

    # Find membership
    membership = db(
        (db.team_member.team_id == team_id) &
        (db.team_member.user_id == user_id)
    ).select().first()

    if not membership:
        return jsonify({'error': 'Team member not found'}), 404

    # Update role
    membership.update_record(role=data['role'])
    db.commit()

    return jsonify({
        'message': 'Team member role updated successfully',
        'user_id': user_id,
        'role': data['role']
    }), 200


@teams_bp.route('/api/v1/teams/<int:team_id>/members/<int:user_id>', methods=['DELETE'])
@token_required
@requires_team_role('team_id', 'TeamAdmin')
@audit_log('team_member_removed')
def remove_team_member(team_id, user_id):
    """Remove member from team."""
    db = current_app.db

    # Find and delete membership
    deleted = db(
        (db.team_member.team_id == team_id) &
        (db.team_member.user_id == user_id)
    ).delete()

    if deleted == 0:
        return jsonify({'error': 'Team member not found'}), 404

    db.commit()

    return jsonify({
        'message': 'Team member removed successfully'
    }), 200
