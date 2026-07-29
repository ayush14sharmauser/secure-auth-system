import re
from dataclasses import dataclass, field
from typing import TypeAlias

from email_validator import EmailNotValidError, validate_email
from zxcvbn import zxcvbn

# ==========================================================
# Constants
# ==========================================================

MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 50

MAX_EMAIL_LENGTH = 254  # RFC 5321

# bcrypt ignores bytes beyond its maximum input size.
# Limiting password length avoids unexpected behavior and
# excessively large inputs.
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

# ==========================================================
# Compiled Regex Patterns
# ==========================================================

USERNAME_REGEX = re.compile(
    rf"^[a-z0-9_]{{{MIN_USERNAME_LENGTH},{MAX_USERNAME_LENGTH}}}$"
)

UPPERCASE_REGEX = re.compile(r"[A-Z]")
LOWERCASE_REGEX = re.compile(r"[a-z]")
DIGIT_REGEX = re.compile(r"\d")
SPECIAL_REGEX = re.compile(r"[^\w\s]")

# ==========================================================
# Type Aliases
# ==========================================================

ValidationErrors: TypeAlias = list[str]

# ==========================================================
# Result Objects
# ==========================================================


@dataclass(frozen=True)
class EmailValidationResult:
    is_valid: bool
    normalized_email: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class PasswordValidationResult:
    is_valid: bool
    errors: ValidationErrors = field(default_factory=list)


@dataclass(frozen=True)
class UsernameValidationResult:
    is_valid: bool
    normalized_username: str | None = None
    errors: ValidationErrors = field(default_factory=list)

# ==========================================================
# Username Validation
# ==========================================================


def normalize_username(username: str) -> str:
    """
    Normalize usernames for consistent storage and comparison.
    """
    return username.strip().lower()


def validate_username(username: str) -> UsernameValidationResult:
    """
    Validates username format.

    Rules:
    - 3-50 characters
    - lowercase letters
    - numbers
    - underscores
    """

    if not username or not isinstance(username, str):
        return UsernameValidationResult(
            False,
            None,
            ["Username is required."]
        )

    normalized = normalize_username(username)
    errors: ValidationErrors = []

    if len(normalized) > MAX_USERNAME_LENGTH:
        errors.append(
            f"Username must be at most {MAX_USERNAME_LENGTH} characters."
        )

    if not USERNAME_REGEX.fullmatch(normalized):
        errors.append(
            "Username may contain only lowercase letters, "
            "numbers, and underscores."
        )

    return UsernameValidationResult(
        is_valid=not errors,
        normalized_username=normalized if not errors else None,
        errors=errors
    )

# ==========================================================
# Email Validation
# ==========================================================


def validate_email_address(email: str) -> EmailValidationResult:
    """
    Validate email syntax and normalize it.

    check_deliverability=False avoids DNS lookups,
    making registration fast and deterministic.
    """

    if not email or not isinstance(email, str):
        return EmailValidationResult(
            False,
            None,
            "Email is required."
        )

    email = email.strip()

    if len(email) > MAX_EMAIL_LENGTH:
        return EmailValidationResult(
            False,
            None,
            f"Email must not exceed {MAX_EMAIL_LENGTH} characters."
        )

    try:
        email_info = validate_email(
            email,
            check_deliverability=False
        )

        return EmailValidationResult(
            True,
            email_info.normalized,
            None
        )

    except EmailNotValidError as exc:
        return EmailValidationResult(
            False,
            None,
            str(exc)
        )

# ==========================================================
# Password Validation
# ==========================================================


def validate_password_strength(password: str) -> PasswordValidationResult:
    """
    Password Policy

    - 12-128 characters
    - uppercase letter
    - lowercase letter
    - digit
    - special character
    - zxcvbn score >= 3
    """

    if not password or not isinstance(password, str):
        return PasswordValidationResult(
            False,
            ["Password is required."]
        )

    errors: ValidationErrors = []

    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )

    if len(password) > MAX_PASSWORD_LENGTH:
        errors.append(
            f"Password must not exceed {MAX_PASSWORD_LENGTH} characters."
        )

    if not UPPERCASE_REGEX.search(password):
        errors.append(
            "Password must contain at least one uppercase letter."
        )

    if not LOWERCASE_REGEX.search(password):
        errors.append(
            "Password must contain at least one lowercase letter."
        )

    if not DIGIT_REGEX.search(password):
        errors.append(
            "Password must contain at least one digit."
        )

    if not SPECIAL_REGEX.search(password):
        errors.append(
            "Password must contain at least one special character."
        )

    # Only perform entropy analysis if the password
    # already satisfies the basic policy.
    if not errors:

        analysis = zxcvbn(password)

        if analysis["score"] < 3:

            feedback = analysis.get("feedback", {})

            warning = feedback.get("warning", "")

            suggestions = feedback.get(
                "suggestions",
                ["Choose a stronger password."]
            )

            entropy_message = " ".join(
                item for item in [warning, *suggestions] if item
            )

            errors.append(
                entropy_message or "Password is too weak."
            )

    return PasswordValidationResult(
        is_valid=not errors,
        errors=errors
    )