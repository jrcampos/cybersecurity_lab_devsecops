"""Security tests for F01: /files path traversal (R6); also covers F02,
missing authentication on /files (R1)."""
import pytest
import baseline_secure_coding_api as api

SECRET = "TOP-SECRET-OUTSIDE-CONTENT"


@pytest.fixture
def materials(tmp_path, monkeypatch):
    mat = tmp_path / "materials"
    mat.mkdir()
    (mat / "notes.txt").write_text("allowed content", encoding="utf-8")
    (mat / "sub").mkdir()
    (mat / "sub" / "deep.txt").write_text("deep content", encoding="utf-8")
    (tmp_path / "secret.txt").write_text(SECRET, encoding="utf-8")
    # sibling directory sharing the "materials" prefix
    (tmp_path / "materials_private").mkdir()
    (tmp_path / "materials_private" / "x.txt").write_text(SECRET, encoding="utf-8")
    monkeypatch.setattr(api, "MATERIALS_DIR", mat)
    return tmp_path


def login_alice(client):
    client.post("/login", data={"username": "alice", "password": "alicepw"})


def get(client, path):
    return client.get("/files", query_string={"path": path})


def test_authenticated_user_can_download_material(client, materials):
    login_alice(client)
    response = get(client, "notes.txt")
    assert response.status_code == 200
    assert response.data == b"allowed content"
    assert get(client, "sub/deep.txt").data == b"deep content"


def test_unauthenticated_download_rejected(client, materials):
    response = get(client, "notes.txt")
    assert response.status_code in (401, 403)
    assert b"allowed content" not in response.data


@pytest.mark.parametrize("path", [
    "../secret.txt",
    "sub/../../secret.txt",
    "../materials_private/x.txt",
])
def test_parent_traversal_blocked(client, materials, path):
    login_alice(client)
    response = get(client, path)
    assert response.status_code in (400, 403, 404)
    assert SECRET.encode() not in response.data


def test_absolute_path_blocked(client, materials):
    # Variation: pathlib discards the base when the right operand is absolute
    login_alice(client)
    response = get(client, str(materials / "secret.txt"))
    assert response.status_code in (400, 403, 404)
    assert SECRET.encode() not in response.data


def test_traversal_blocked_for_unauthenticated_too(client, materials):
    response = get(client, "../secret.txt")
    assert SECRET.encode() not in response.data
