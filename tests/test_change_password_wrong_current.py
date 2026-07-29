from uuid import uuid4


def test_change_password_wrong_current(client):
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

    access_token = login.get_json()["access_token"]

    response = client.post(
        "/api/auth/change-password",
        json={
            "current_password": "WrongPassword123!",
            "new_password": "NewStrongPass123!"
        },
        headers={
            "Authorization": f"Bearer {access_token}"
        },
    )

    assert response.status_code == 400

    data = response.get_json()

    assert data["success"] is False