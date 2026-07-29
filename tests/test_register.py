from uuid import uuid4


def test_register_success(client):
    payload = {
        "username": f"user_{uuid4().hex[:8]}",
        "email": f"{uuid4().hex[:8]}@example.com",
        "password": "StrongPass123!"
    }

    response = client.post(
        "/api/auth/register",
        json=payload,
    )

    assert response.status_code == 201

    data = response.get_json()

    assert data["success"] is True