import os
import sys
from datetime import datetime, timedelta
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from database import Base, get_db  # noqa: E402
import main as main_module  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    main_module.shared_scans.clear()
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    main_module.shared_scans.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def create_test_scan(token, title="Share test finding"):
    response = client.post(
        "/scans",
        json={
            "title": title,
            "description": "Test finding details",
            "severity": "high",
            "affected_component": "test endpoint",
        },
        headers=auth_headers(token),
    )
    assert response.status_code == 201
    return response.json()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    # TODO: add assertions for search results
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


def test_share_link_returns_absolute_url_and_public_scan():
    token = register_and_login()
    scan = create_test_scan(token)

    share_response = client.post(
        f"/scans/{scan['id']}/share",
        json={},
        headers=auth_headers(token),
    )

    assert share_response.status_code == 200
    share_url = share_response.json()["share_url"]
    assert share_url.startswith("http://testserver/share/")

    public_response = client.get(urlparse(share_url).path)
    assert public_response.status_code == 200
    assert public_response.json()["id"] == scan["id"]


def test_password_protected_share_requires_and_checks_password():
    token = register_and_login()
    scan = create_test_scan(token)
    share_response = client.post(
        f"/scans/{scan['id']}/share",
        json={"password": "stakeholder-password"},
        headers=auth_headers(token),
    )
    share_path = urlparse(share_response.json()["share_url"]).path

    assert client.get(share_path).status_code == 401
    assert client.get(share_path, params={"password": "wrong"}).status_code == 401
    valid_response = client.get(
        share_path,
        params={"password": "stakeholder-password"},
    )
    assert valid_response.status_code == 200
    assert valid_response.json()["id"] == scan["id"]


def test_share_link_expires_after_24_hours():
    token = register_and_login()
    scan = create_test_scan(token)
    share_response = client.post(
        f"/scans/{scan['id']}/share",
        json={},
        headers=auth_headers(token),
    )
    share_path = urlparse(share_response.json()["share_url"]).path
    share_token = share_path.rsplit("/", 1)[-1]
    main_module.shared_scans[share_token]["expires_at"] = (
        datetime.utcnow() - timedelta(seconds=1)
    )

    assert client.get(share_path).status_code == 404


def test_user_cannot_read_or_share_another_users_scan():
    owner_token = register_and_login()
    scan = create_test_scan(owner_token)
    other_token = register_and_login(
        username="bob",
        email="bob@example.com",
        password="password123",
    )

    get_response = client.get(
        f"/scans/{scan['id']}",
        headers=auth_headers(other_token),
    )
    share_response = client.post(
        f"/scans/{scan['id']}/share",
        json={},
        headers=auth_headers(other_token),
    )

    assert get_response.status_code == 404
    assert share_response.status_code == 404


def test_search_returns_only_current_users_scans():
    first_token = register_and_login()
    create_test_scan(first_token, title="Private report Alpha")
    second_token = register_and_login(
        username="bob",
        email="bob@example.com",
        password="password123",
    )
    create_test_scan(second_token, title="Private report Beta")

    response = client.get(
        "/scans/search?q=Private",
        headers=auth_headers(first_token),
    )

    assert response.status_code == 200
    assert [item["title"] for item in response.json()["results"]] == [
        "Private report Alpha"
    ]
