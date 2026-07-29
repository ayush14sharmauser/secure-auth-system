from datetime import UTC, datetime
from typing import Any

from flask import Response, jsonify


def utc_now_iso() -> str:
    """
    Return the current UTC timestamp in ISO 8601 format.
    """
    return datetime.now(UTC).isoformat()


def success_response(
    message: str,
    status: int = 200,
    **extra: Any,
) -> tuple[Response, int]:
    """
    Standard success response.
    """
    payload = {
        "success": True,
        "message": message,
        "timestamp": utc_now_iso(),
    }

    payload.update(extra)

    return jsonify(payload), status


def error_response(
    message: str,
    status: int = 400,
    details: Any = None,
) -> tuple[Response, int]:
    """
    Standard error response.
    """
    payload = {
        "success": False,
        "error": {
            "message": message,
        },
        "timestamp": utc_now_iso(),
    }

    if details is not None:
        payload["error"]["details"] = details

    return jsonify(payload), status