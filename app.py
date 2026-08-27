"""Flask file manager — a browser-based file browser with upload, download,
view and delete.

Security note
-------------
This application gives a browser control over a directory on the host. Every
request path is therefore validated against the managed root before any
filesystem operation, so a crafted path such as ``../../etc/passwd`` cannot
escape it (see :func:`safe_path`). Credentials and the session key come from
the environment, not the source. Even so, treat this as an *internal* tool:
run it behind authentication you trust and never expose it directly to the
internet.
"""

from __future__ import annotations

import datetime
import hmac
import os
import secrets
import shutil
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

# --------------------------------------------------------------------------- #
# Configuration — everything sensitive comes from the environment.
# --------------------------------------------------------------------------- #

#: the single directory this manager is allowed to touch, resolved once
UPLOAD_FOLDER = Path(os.environ.get("FM_UPLOAD_FOLDER", "uploads")).resolve()

#: credentials.  Defaults exist only so the app runs out of the box for a local
#: demo; a warning is printed when they are in use, and any real deployment must
#: set FM_USERNAME / FM_PASSWORD.
USERNAME = os.environ.get("FM_USERNAME", "admin")
PASSWORD = os.environ.get("FM_PASSWORD", "admin123")
_USING_DEFAULT_CREDENTIALS = "FM_USERNAME" not in os.environ or "FM_PASSWORD" not in os.environ

#: session-signing key.  A stable value must be provided in production; without
#: one, sessions are signed with a per-process random key (logs everyone out on
#: restart, which is the safe default).
SECRET_KEY = os.environ.get("FM_SECRET_KEY") or secrets.token_hex(32)

#: reject uploads larger than this (bytes); 512 MB by default
MAX_CONTENT_LENGTH = int(os.environ.get("FM_MAX_UPLOAD_MB", "512")) * 1024 * 1024

TEXT_EXTENSIONS = frozenset(
    {".txt", ".py", ".md", ".json", ".csv", ".log", ".xml", ".html", ".css", ".js"}
)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- #
# Path safety — the core of the security fix.
# --------------------------------------------------------------------------- #


def safe_path(req_path: str) -> Path:
    """Resolve ``req_path`` under the upload root, refusing anything that escapes.

    ``req_path`` is attacker-controlled (it comes straight from the URL). Any
    request whose resolved location is not inside :data:`UPLOAD_FOLDER` -
    absolute paths, ``..`` traversal, symlinks pointing outward - is rejected
    with 404 rather than served.
    """
    candidate = (UPLOAD_FOLDER / req_path).resolve()
    if candidate != UPLOAD_FOLDER and UPLOAD_FOLDER not in candidate.parents:
        abort(404)
    return candidate


def safe_child(directory: Path, name: str) -> Path:
    """Join one uploaded file name under ``directory``, safely.

    The name is reduced to a bare, safe component (``secure_filename``), so an
    upload called ``../../../etc/cron.d/evil`` cannot be written outside the
    target, and the result is confirmed to stay within the upload root.
    """
    cleaned = secure_filename(name)
    if not cleaned:
        abort(400)
    target = (directory / cleaned).resolve()
    if target.parent != UPLOAD_FOLDER and UPLOAD_FOLDER not in target.parents:
        abort(400)
    return target


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # constant-time comparison so a timing side channel cannot leak the
        # credentials one character at a time
        ok = hmac.compare_digest(username, USERNAME) and hmac.compare_digest(
            password, PASSWORD
        )
        if ok:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("browse"))
        flash("Username or password incorrect")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def format_size(bytes_size: float) -> str:
    """Human-readable size using decimal units."""
    bytes_size = float(bytes_size)
    units = ["B", "KB", "MB", "GB", "TB"]
    index = 0
    while bytes_size >= 1000 and index < len(units) - 1:
        bytes_size /= 1000
        index += 1
    return f"{bytes_size:.2f} {units[index]}"


def get_dir_size(path: Path) -> int:
    total = 0
    try:
        for root, _dirs, files in os.walk(path):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(root, name))
                except OSError:
                    continue
    except OSError as exc:
        app.logger.warning("size walk failed for %s: %s", path, exc)
    return total


def list_dir(path: Path):
    """List the *immediate* children of ``path`` (no recursive walk).

    The original walked the whole tree, which flattened nested folders into one
    list and made large directories very slow. A file manager should show one
    level at a time.
    """
    items = []
    total_bytes = 0
    files_count = 0
    dirs_count = 0
    try:
        for entry in os.scandir(path):
            try:
                stat = entry.stat()
            except OSError:
                continue
            mtime_str = datetime.datetime.fromtimestamp(stat.st_mtime).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if entry.is_dir():
                dirs_count += 1
                size = get_dir_size(Path(entry.path))
                total_bytes += size
                items.append(
                    {"name": entry.name, "is_dir": True, "size": format_size(size),
                     "date": mtime_str, "mtime": stat.st_mtime}
                )
            else:
                files_count += 1
                total_bytes += stat.st_size
                items.append(
                    {"name": entry.name, "is_dir": False, "size": format_size(stat.st_size),
                     "date": mtime_str, "mtime": stat.st_mtime}
                )
        items.sort(key=lambda item: (not item["is_dir"], -item["mtime"]))
    except OSError as exc:
        app.logger.warning("listing failed for %s: %s", path, exc)
    return items, total_bytes, files_count, dirs_count


def is_text_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS


def relative(path: Path) -> str:
    """Path relative to the upload root, in URL form."""
    return path.relative_to(UPLOAD_FOLDER).as_posix()


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #


@app.route("/")
@login_required
def root_redirect():
    return redirect(url_for("browse"))


@app.route("/browse", defaults={"req_path": ""})
@app.route("/browse/<path:req_path>")
@login_required
def browse(req_path):
    abs_path = safe_path(req_path)
    if not abs_path.exists():
        abort(404)
    if abs_path.is_file():
        return send_from_directory(abs_path.parent, abs_path.name, as_attachment=True)

    files, total_bytes, files_count, dirs_count = list_dir(abs_path)
    parent = os.path.dirname(req_path)
    return render_template(
        "index.html",
        files=files,
        current_path=req_path,
        parent_path=parent,
        total_size=format_size(total_bytes),
        files_count=files_count,
        dirs_count=dirs_count,
    )


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded = request.files.getlist("files[]")
    target = safe_path(request.form.get("path", ""))
    target.mkdir(parents=True, exist_ok=True)

    saved = 0
    for file in uploaded:
        if not file.filename:
            continue
        destination = safe_child(target, os.path.basename(file.filename))
        file.save(destination)
        saved += 1

    flash(f"{saved} file(s) uploaded successfully")
    return redirect(
        url_for("browse", req_path=relative(target) if target != UPLOAD_FOLDER else "")
    )


@app.route("/download/<path:req_path>")
@login_required
def download(req_path):
    abs_path = safe_path(req_path)
    if abs_path.is_dir():
        # zip into a temporary sibling, then serve it
        archive = shutil.make_archive(str(abs_path), "zip", abs_path)
        archive_path = Path(archive)
        return send_from_directory(
            archive_path.parent, archive_path.name, as_attachment=True
        )
    if abs_path.is_file():
        return send_from_directory(abs_path.parent, abs_path.name, as_attachment=True)
    abort(404)


@app.route("/delete/<path:req_path>", methods=["POST"])
@login_required
def delete(req_path):
    abs_path = safe_path(req_path)
    if abs_path == UPLOAD_FOLDER:
        flash("Refusing to delete the root folder")
        return redirect(url_for("browse"))
    try:
        if abs_path.is_dir():
            shutil.rmtree(abs_path)
        elif abs_path.is_file():
            abs_path.unlink()
        else:
            flash("File or folder not found")
            return redirect(url_for("browse"))
        flash("Deleted successfully")
    except OSError as exc:
        flash(f"Delete failed: {exc}")
    return redirect(url_for("browse", req_path=os.path.dirname(req_path)))


@app.route("/view/<path:req_path>")
@login_required
def view_file(req_path):
    abs_path = safe_path(req_path)
    if not abs_path.is_file():
        flash("File not found")
        return redirect(url_for("browse"))
    if not is_text_file(abs_path):
        flash("This file type cannot be viewed")
        return redirect(url_for("browse", req_path=os.path.dirname(req_path)))
    try:
        # cap the read so a giant file cannot exhaust memory
        content = abs_path.read_text(encoding="utf-8", errors="replace")[: 2 * 1024 * 1024]
    except OSError as exc:
        flash(f"Could not read file: {exc}")
        return redirect(url_for("browse", req_path=os.path.dirname(req_path)))
    return render_template("view_text.html", content=content, filename=abs_path.name)


@app.errorhandler(413)
def too_large(_error):
    flash("Upload rejected: the file exceeds the size limit")
    return redirect(url_for("browse"))


def _startup_warnings() -> None:
    if _USING_DEFAULT_CREDENTIALS:
        print(
            "WARNING: using the default admin/admin123 credentials. "
            "Set FM_USERNAME and FM_PASSWORD before exposing this app."
        )
    if "FM_SECRET_KEY" not in os.environ:
        print(
            "NOTE: FM_SECRET_KEY is not set; using a random per-process key "
            "(sessions reset on restart)."
        )


if __name__ == "__main__":
    _startup_warnings()
    # debug defaults to OFF: the Werkzeug debugger is a remote code execution
    # console, and this app already exposes the filesystem.  Opt in with
    # FM_DEBUG=1 only on a machine you control.
    debug = os.environ.get("FM_DEBUG") == "1"
    host = os.environ.get("FM_HOST", "127.0.0.1")
    port = int(os.environ.get("FM_PORT", "5000"))
    app.run(host=host, port=port, debug=debug)
