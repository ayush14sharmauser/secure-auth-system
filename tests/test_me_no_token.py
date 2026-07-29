def test_me_no_token(client):
    response = client.get("/api/auth/me")

    assert response.status_code == 401

    data = response.get_json()

    assert data["success"] is False