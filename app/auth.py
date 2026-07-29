from flask import Blueprint, request, current_app
from flask.typing import ResponseReturnValue
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import TokenBlocklist, User
from app.utils.responses import error_response, success_response
from app.utils.validators import (
    validate_email_address,
    validate_password_strength,
    validate_username,
)
ERROR_TOKEN_EXPIRED = "Token has expired."
ERROR_TOKEN_INVALID = "Invalid token."
ERROR_TOKEN_MISSING = "Authorization token is missing."
ERROR_TOKEN_REVOKED = "Token has been revoked."
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# ── Error messages ───────────────────────────────────────────────
ERROR_INVALID_JSON = "Request body must be valid JSON"
ERROR_VALIDATION_FAILED = "Validation failed"
ERROR_USERNAME_INVALID = "Username validation failed"
ERROR_EMAIL_INVALID = "Invalid email format"
ERROR_PASSWORD_WEAK = "Password does not meet security requirements."
ERROR_USERNAME_EXISTS = "Username already exists"
ERROR_EMAIL_EXISTS = "Email already exists"
ERROR_DUPLICATE = "Username or email already exists"
ERROR_INVALID_CREDENTIALS = "Invalid email or password"
ERROR_USER_NOT_FOUND = "User not found"
ERROR_CURRENT_PASSWORD_INCORRECT = "Current password is incorrect"
ERROR_NEW_PASSWORD_SAME = (
    "New password must be different from the current password"
)
ERROR_INTERNAL = "Internal server error"

# ── Success messages ─────────────────────────────────────────────
MSG_REGISTER_SUCCESS = "User registered successfully"
MSG_LOGIN_SUCCESS = "Login successful"
MSG_ME_SUCCESS = "User retrieved successfully"
MSG_REFRESH_SUCCESS = "Access token refreshed successfully"
MSG_LOGOUT_SUCCESS = "Logout successful"
MSG_PASSWORD_CHANGED = "Password changed successfully. Please log in again."


def _revoke_current_token() -> None:
    """Add the current JWT's jti to the blocklist and commit."""
    jti = get_jwt()["jti"]
    db.session.add(TokenBlocklist(jti=jti))
    db.session.commit()


@auth_bp.post("/register")
def register() -> ResponseReturnValue:
    data = request.get_json(silent=True)

    if data is None:
        return error_response(
            ERROR_INVALID_JSON,
            status=400,
        )

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    # ── Required-field validation ────────────────────────────────
    errors = {}

    if not isinstance(username, str) or not username.strip():
        errors["username"] = ["Username is required."]

    if not isinstance(email, str) or not email.strip():
        errors["email"] = ["Email is required."]

    if not isinstance(password, str) or not password:
        errors["password"] = ["Password is required."]

    if errors:
        return error_response(
            ERROR_VALIDATION_FAILED,
            status=400,
            details=errors,
        )

    # ── Username validation & normalization ──────────────────────
    username_result = validate_username(username)
    if not username_result.is_valid:
        return error_response(
            ERROR_USERNAME_INVALID,
            status=400,
            details=username_result.errors,
        )

    normalized_username = username_result.normalized_username

    # ── Email validation & normalization ─────────────────────────
    email_result = validate_email_address(email)
    if not email_result.is_valid:
        return error_response(
            ERROR_EMAIL_INVALID,
            status=400,
            details=email_result.error,
        )

    normalized_email = email_result.normalized_email

    # ── Password strength validation ─────────────────────────────
    password_result = validate_password_strength(password)
    if not password_result.is_valid:
        return error_response(
            ERROR_PASSWORD_WEAK,
            status=400,
            details=password_result.errors,
        )

    # ── Uniqueness validation & create user ──────────────────────
    try:
        existing_username = db.session.execute(
            select(User).where(User.username == normalized_username)
        ).scalar_one_or_none()

        existing_email = db.session.execute(
            select(User).where(User.email == normalized_email)
        ).scalar_one_or_none()

        if existing_username:
            return error_response(
                ERROR_USERNAME_EXISTS,
                status=409,
            )

        if existing_email:
            return error_response(
                ERROR_EMAIL_EXISTS,
                status=409,
            )

        user = User(
            username=normalized_username,
            email=normalized_email,
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        current_app.logger.info(
            "User %s registered successfully",
            user.id,
        )

        return success_response(
            MSG_REGISTER_SUCCESS,
            status=201,
            user=user.to_dict(),
        )

    except IntegrityError:
        db.session.rollback()
        return error_response(
            ERROR_DUPLICATE,
            status=409,
        )
    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Unexpected error during user registration"
        )
        return error_response(
            ERROR_INTERNAL,
            status=500,
        )


@auth_bp.post("/login")
def login() -> ResponseReturnValue:
    data = request.get_json(silent=True)

    if data is None:
        return error_response(
            ERROR_INVALID_JSON,
            status=400,
        )

    email = data.get("email")
    password = data.get("password")

    # ── Required-field validation ────────────────────────────────
    errors = {}

    if not isinstance(email, str) or not email.strip():
        errors["email"] = ["Email is required."]

    if not isinstance(password, str) or not password:
        errors["password"] = ["Password is required."]

    if errors:
        return error_response(
            ERROR_VALIDATION_FAILED,
            status=400,
            details=errors,
        )

    # ── Email validation & normalization ─────────────────────────
    email_result = validate_email_address(email)
    if not email_result.is_valid:
        return error_response(
            ERROR_INVALID_CREDENTIALS,
            status=401,
        )

    normalized_email = email_result.normalized_email

    # ── Find user & authenticate ─────────────────────────────────
    # Never reveal which part failed — always return the same message
    # and status code for both wrong email and wrong password.
    try:
        user = db.session.execute(
            select(User).where(User.email == normalized_email)
        ).scalar_one_or_none()

        if user is None or not user.check_password(password):
            return error_response(
                ERROR_INVALID_CREDENTIALS,
                status=401,
            )

        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))

        current_app.logger.info(
            "User %s logged in successfully",
            user.id,
        )

        return success_response(
            MSG_LOGIN_SUCCESS,
            access_token=access_token,
            refresh_token=refresh_token,
            user=user.to_dict(),
        )

    except Exception:
        current_app.logger.exception(
            "Unexpected error during user login"
        )
        return error_response(
            ERROR_INTERNAL,
            status=500,
        )


@auth_bp.get("/me")
@jwt_required()
def me() -> ResponseReturnValue:
    user_id = get_jwt_identity()

    try:
        user = db.session.get(User, int(user_id))

        if user is None:
            return error_response(
                ERROR_USER_NOT_FOUND,
                status=404,
            )

        return success_response(
            MSG_ME_SUCCESS,
            user=user.to_dict(),
        )

    except Exception:
        current_app.logger.exception(
            "Unexpected error while fetching authenticated user"
        )
        return error_response(
            ERROR_INTERNAL,
            status=500,
        )


@auth_bp.post("/refresh")
@jwt_required(refresh=True)
def refresh() -> ResponseReturnValue:
    try:
        user_id = get_jwt_identity()

        user = db.session.get(User, int(user_id))

        if user is None:
            return error_response(
                ERROR_USER_NOT_FOUND,
                status=404,
            )

        access_token = create_access_token(identity=str(user.id))

        return success_response(
            MSG_REFRESH_SUCCESS,
            access_token=access_token,
        )

    except Exception:
        current_app.logger.exception(
            "Unexpected error while refreshing access token"
        )
        return error_response(
            ERROR_INTERNAL,
            status=500,
        )


@auth_bp.post("/logout")
@jwt_required()
def logout() -> ResponseReturnValue:
    try:
        user_id = get_jwt_identity()

        _revoke_current_token()

        current_app.logger.info(
            "User %s logged out",
            user_id,
        )

        return success_response(
            MSG_LOGOUT_SUCCESS,
        )

    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Unexpected error during logout"
        )
        return error_response(
            ERROR_INTERNAL,
            status=500,
        )


@auth_bp.post("/logout/refresh")
@jwt_required(refresh=True)
def logout_refresh() -> ResponseReturnValue:
    try:
        user_id = get_jwt_identity()

        _revoke_current_token()

        current_app.logger.info(
            "User %s logged out (refresh token revoked)",
            user_id,
        )

        return success_response(
            MSG_LOGOUT_SUCCESS,
        )

    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Unexpected error during refresh token logout"
        )
        return error_response(
            ERROR_INTERNAL,
            status=500,
        )


@auth_bp.post("/change-password")
@jwt_required()
def change_password() -> ResponseReturnValue:
    data = request.get_json(silent=True)

    if data is None:
        return error_response(
            ERROR_INVALID_JSON,
            status=400,
        )

    current_password = data.get("current_password")
    new_password = data.get("new_password")

    # ── Required-field validation ────────────────────────────────
    errors = {}

    if not isinstance(current_password, str) or not current_password:
        errors["current_password"] = ["Current password is required."]

    if not isinstance(new_password, str) or not new_password:
        errors["new_password"] = ["New password is required."]

    if errors:
        return error_response(
            ERROR_VALIDATION_FAILED,
            status=400,
            details=errors,
        )

    try:
        user_id = get_jwt_identity()
        user = db.session.get(User, int(user_id))

        if user is None:
            return error_response(
                ERROR_USER_NOT_FOUND,
                status=404,
            )

        if not user.check_password(current_password):
            return error_response(
                ERROR_CURRENT_PASSWORD_INCORRECT,
                status=400,
            )

        if user.check_password(new_password):
            return error_response(
                ERROR_NEW_PASSWORD_SAME,
                status=400,
            )

        password_result = validate_password_strength(new_password)
        if not password_result.is_valid:
            return error_response(
                ERROR_PASSWORD_WEAK,
                status=400,
                details=password_result.errors,
            )

        user.set_password(new_password)
        db.session.commit()

        current_app.logger.info(
            "User %s changed password",
            user.id,
        )

        return success_response(
            MSG_PASSWORD_CHANGED,
            status=200,
        )

    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Unexpected error during password change"
        )
        return error_response(
            ERROR_INTERNAL,
            status=500,
        )