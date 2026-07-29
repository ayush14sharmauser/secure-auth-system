from uuid import uuid4


def test_register_duplicate_email(client):
    payload = {
        "username": f"user_{uuid4().hex[:8]}",
        "email": f"{uuid4().hex[:8]}@example.com",
        "password": "StrongPass123!"
    }

    first = client.post("/api/auth/register", json=payload)
    assert first.status_code == 201

    second = client.post("/api/auth/register", json=payload)

    assert second.status_code == 409

    data = second.get_json()

    assert data["success"] is False