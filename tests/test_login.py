from uuid import uuid4


def test_login_success(client):
    payload = {
        "username": f"user_{uuid4().hex[:8]}",
        "email": f"{uuid4().hex[:8]}@example.com",
        "password": "StrongPass123!"
    }

    register = client.post(
        "/api/auth/register",
        json=payload,
    )

    assert register.status_code == 201

    response = client.post(
        "/api/auth/login",
        json={
            "email": payload["email"],
            "password": payload["password"],
        },
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["message"] == "Login successful"
    assert data["user"]["email"] == payload["email"]