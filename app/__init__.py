from flask import Flask
from sqlalchemy import select

from app.auth import (
    ERROR_TOKEN_EXPIRED,
    ERROR_TOKEN_INVALID,
    ERROR_TOKEN_MISSING,
    ERROR_TOKEN_REVOKED,
    auth_bp,
)
from app.config import Config
from app.extensions import bcrypt, db, jwt, migrate
from app.models import TokenBlocklist
from app.routes import main
from app.utils.responses import error_response


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    bcrypt.init_app(app)

    # ── JWT blocklist ────────────────────────────────────────────

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]

        token = db.session.execute(
            select(TokenBlocklist).where(TokenBlocklist.jti == jti)
        ).scalar_one_or_none()

        return token is not None

    # ── JWT error callbacks ──────────────────────────────────────

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return error_response(
            ERROR_TOKEN_REVOKED,
            status=401,
        )

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return error_response(
            ERROR_TOKEN_EXPIRED,
            status=401,
        )

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return error_response(
            ERROR_TOKEN_INVALID,
            status=401,
        )

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return error_response(
            ERROR_TOKEN_MISSING,
            status=401,
        )

    app.register_blueprint(main)
    app.register_blueprint(auth_bp)

    return app