from uuid import uuid4


def test_login_invalid_password(client):
    payload = {
        "username": f"user_{uuid4().hex[:8]}",
        "email": f"{uuid4().hex[:8]}@example.com",
        "password": "StrongPass123!"
    }

    client.post("/api/auth/register", json=payload)

    response = client.post(
        "/api/auth/login",
        json={
            "email": payload["email"],
            "password": "WrongPassword123!"
        },
    )

    assert response.status_code == 401

    data = response.get_json()

    assert data["success"] is False