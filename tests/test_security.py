"""Security regression tests for the file manager.

The point of these is narrow and important: prove that the path-traversal hole
that used to exist is actually closed, and stays closed. Each test drives the
real Flask app through its routes.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A logged-in test client whose upload root is an isolated temp dir.

    A canary file is planted *outside* that root so a successful traversal
    would be observable - and the tests assert it never is.
    """
    root = tmp_path / "uploads"
    root.mkdir()
    (root / "hello.txt").write_text("inside the sandbox", encoding="utf-8")

    canary = tmp_path / "secret.txt"
    canary.write_text("TOP SECRET - must never be reachable", encoding="utf-8")

    monkeypatch.setenv("FM_UPLOAD_FOLDER", str(root))
    monkeypatch.setenv("FM_USERNAME", "tester")
    monkeypatch.setenv("FM_PASSWORD", "correct horse")
    monkeypatch.setenv("FM_SECRET_KEY", "test-key")

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import app as app_module

    importlib.reload(app_module)
    app_module.app.config.update(TESTING=True)

    test_client = app_module.app.test_client()
    test_client.post("/login", data={"username": "tester", "password": "correct horse"})
    test_client._canary = canary  # type: ignore[attr-defined]
    return test_client


class TestAuthentication:
    def test_browse_requires_login(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FM_UPLOAD_FOLDER", str(tmp_path))
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        import app as app_module

        importlib.reload(app_module)
        anon = app_module.app.test_client()
        response = anon.get("/browse", follow_redirects=False)
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]

    def test_wrong_password_is_rejected(self, client):
        client.get("/logout")
        response = client.post(
            "/login", data={"username": "tester", "password": "wrong"}, follow_redirects=True
        )
        assert b"incorrect" in response.data.lower()

    def test_correct_login_reaches_browser(self, client):
        response = client.get("/browse")
        assert response.status_code == 200
        assert b"hello.txt" in response.data


class TestPathTraversal:
    """The vulnerability that motivated the rewrite. None of these may succeed."""

    @pytest.mark.parametrize(
        "attack",
        [
            "/browse/../secret.txt",
            "/browse/../../secret.txt",
            "/browse/..%2f..%2fsecret.txt",
            "/download/../secret.txt",
            "/view/../secret.txt",
        ],
    )
    def test_read_traversal_is_blocked(self, client, attack):
        response = client.get(attack, follow_redirects=False)
        # either rejected outright, or bounced back inside - never the canary
        assert response.status_code in (400, 404, 302)
        assert b"TOP SECRET" not in response.data

    def test_delete_traversal_cannot_remove_outside_files(self, client):
        canary: Path = client._canary  # type: ignore[attr-defined]
        assert canary.exists()
        client.post("/delete/../secret.txt", follow_redirects=False)
        assert canary.exists(), "a traversal delete removed a file outside the root"

    def test_absolute_path_is_rejected(self, client):
        # follow any normalisation redirect; what matters is no file is served
        response = client.get("/browse/%2Fetc%2Fpasswd", follow_redirects=True)
        assert b"root:" not in response.data
        response = client.get("/browse//etc/passwd", follow_redirects=True)
        assert b"root:" not in response.data


class TestUploadSafety:
    def test_upload_stays_inside_the_root(self, client, tmp_path):
        import io

        canary_dir = tmp_path
        data = {
            "path": "",
            "files[]": (io.BytesIO(b"payload"), "../../escape.txt"),
        }
        client.post("/upload", data=data, content_type="multipart/form-data")
        # secure_filename flattens the name; nothing lands outside the root
        assert not (canary_dir / "escape.txt").exists()

    def test_normal_upload_succeeds(self, client):
        import io

        data = {"path": "", "files[]": (io.BytesIO(b"hello world"), "note.txt")}
        response = client.post(
            "/upload", data=data, content_type="multipart/form-data", follow_redirects=True
        )
        assert response.status_code == 200
        assert b"note.txt" in response.data


class TestConfiguration:
    def test_debug_is_off_without_the_env_flag(self, client):
        import app as app_module

        assert app_module.app.debug is False

    def test_secret_key_is_not_the_old_hardcoded_value(self, client):
        import app as app_module

        assert app_module.app.secret_key != "supersecretkey1234"

    def test_upload_size_limit_is_configured(self, client):
        import app as app_module

        assert app_module.app.config["MAX_CONTENT_LENGTH"] > 0
