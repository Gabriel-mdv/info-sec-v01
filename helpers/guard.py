from flask import g, session, abort, url_for
from app import get_db, current_user, log_audit
from helpers import policy

ROLE_BASIC = "basic"
ROLE_USER_ADMIN = "user_admin"
ROLE_DATA_ADMIN = "data_admin"

def check_role_permission(user_role, required_role):
    """Secure role hierarchy check with exact match for admin roles."""
    role_hierarchy = {
        ROLE_BASIC: 0,
        ROLE_USER_ADMIN: 1,
        ROLE_DATA_ADMIN: 1
    }
    user_level = role_hierarchy.get(user_role, -1)
    required_level = role_hierarchy.get(required_role, 0)
    if required_role in [ROLE_USER_ADMIN, ROLE_DATA_ADMIN]:
        return user_role == required_role
    return user_level >= required_level

def guard(action, target=None, forbid_self_delete=True):
     #"""Secure central guard function for action authorization."""
    # Validate inputs
    # if not isinstance(action, str) or (target and not isinstance(target, str)):
    #     log_audit(None, "invalid_request", action, "denied")
    #     abort(400)

    # Enforce authentication and 2FA
    user = current_user()
    if not user or not session.get("verified_2fa"):
        log_audit(None, action, target, "denied")
        abort(403)

    # Check policy
    required_role = policy.policy.get(action)
    if not required_role:
        log_audit(user['andrew_id'], action, target, "denied")
        return False

    # Validate user role
    # if 'role' not in user or not isinstance(user['role'], str):
    #     log_audit(user['andrew_id'], action, target, "denied")
    #     abort(500)
    has_permission = check_role_permission(user['role'], required_role)

    # Enforce self-delete protection
    if forbid_self_delete and action == "delete_user":
        user_id = str(user['id'])
        user_andrew = user['andrew_id']
        if target in [user_id, user_andrew]:
            log_audit(user['andrew_id'], action, target, "denied")
            return False

    # Log all attempts
    outcome = "allowed" if has_permission else "denied"
    log_audit(user['andrew_id'], action, target, outcome)

    return has_permission