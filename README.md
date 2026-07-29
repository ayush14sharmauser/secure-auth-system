# Secure Auth System

A production-ready Flask authentication backend with JWT, PostgreSQL, SQLAlchemy, Alembic, bcrypt, and automated testing.

## Features

- User Registration
- User Login
- JWT Authentication
- Access & Refresh Tokens
- Protected Routes
- Logout
- Refresh Token Rotation
- Password Change
- Token Blocklist
- PostgreSQL Database
- Alembic Migrations
- Pytest Test Suite
- 80% Test Coverage

## Tech Stack

- Python 3.11
- Flask
- PostgreSQL
- SQLAlchemy
- Alembic
- Flask-JWT-Extended
- Flask-Bcrypt
- Pytest

## Run

```bash
pip install -r requirements.txt
flask db upgrade
python run.py
```

## Tests

```bash
python -m pytest
```

## Coverage

```bash
python -m pytest --cov=app --cov-report=term-missing
```
