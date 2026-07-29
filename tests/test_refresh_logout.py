from uuid import uuid4


def test_refresh_logout_success(client):
    payload = {
        "username": f"user_{uuid4().hex[:8]}",
        "email": f"{uuid4().hex[:8]}@example.com",
        "password": "StrongPass123!"
    }

    client.post("/api/auth/register", json=payload)

    login = client.post(
        "/api/auth/login",
        json={
            "email": payload["email"],
            "password": payload["password"],
        },
    )

    refresh_token = login.get_json()["refresh_token"]

    response = client.post(
        "/api/auth/logout/refresh",
        headers={
            "Authorization": f"Bearer {refresh_token}"
        },
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True