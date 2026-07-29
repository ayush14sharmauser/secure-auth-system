def test_invalid_token(client):
    response = client.get(
        "/api/auth/me",
        headers={
            "Authorization": "Bearer invalid_token"
        },
    )

    assert response.status_code == 401

    data = response.get_json()

    assert data["success"] is False