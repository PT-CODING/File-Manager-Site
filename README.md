# 🗂️ File Manager Site

A Flask web application to **browse, upload, download, view and delete** files
and folders from your browser, with a clean bilingual (English/Hebrew)
interface and a login screen.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/Tests-15%20passing-2FD6A4)](tests/test_security.py)
[![License](https://img.shields.io/badge/License-MIT-7B61FF)](LICENSE)
[![CI](https://github.com/PT-CODING/File-Manager-Site/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)

---

## ⚠️ Security model — read this first

This app gives a browser control over a directory on the host machine, so it is
built to keep that control **inside one folder and behind a login**:

- **Path-traversal protection.** Every request path is resolved and checked
  against the managed root before any filesystem operation. A crafted path such
  as `../../etc/passwd` is rejected with `404`, not served. This is covered by
  regression tests in [`tests/test_security.py`](tests/test_security.py).
- **No secrets in the source.** The admin credentials and the session key come
  from environment variables. The built-in `admin` / `admin123` default exists
  only so the app runs for a quick local demo, and it **prints a warning** when
  in use.
- **Uploads are sanitised.** File names are reduced to a safe component, so an
  upload named `../../../etc/cron.d/evil` cannot be written outside the root.
  There is a configurable size limit (512 MB by default).
- **Debug is off by default.** Flask's debugger is a remote code-execution
  console; it is only enabled if you explicitly set `FM_DEBUG=1`.

Even so, this is an **internal tool**. Run it on a trusted network behind
authentication you control — do not expose it directly to the internet.

---

## 🚀 Run it

```bash
git clone https://github.com/PT-CODING/File-Manager-Site.git
cd File-Manager-Site
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000**.

By default it logs in with `admin` / `admin123` and serves an `uploads/` folder
in the project directory.

## 🔧 Configuration

Everything is set through environment variables — nothing sensitive lives in the
code.

| Variable | Default | Purpose |
|---|---|---|
| `FM_USERNAME` | `admin` | login user |
| `FM_PASSWORD` | `admin123` | login password |
| `FM_SECRET_KEY` | random per run | session-signing key (set a stable value in production) |
| `FM_UPLOAD_FOLDER` | `uploads` | the one directory the app may touch |
| `FM_MAX_UPLOAD_MB` | `512` | reject uploads larger than this |
| `FM_HOST` | `127.0.0.1` | bind address |
| `FM_PORT` | `5000` | port |
| `FM_DEBUG` | off | set to `1` to enable the debugger (local only) |

Example — a hardened local run (PowerShell):

```powershell
$env:FM_PASSWORD = 'a long passphrase'
$env:FM_SECRET_KEY = (python -c "import secrets;print(secrets.token_hex(32))")
python app.py
```

## 🧪 Tests

```bash
python -m pytest
```

The suite is deliberately focused on the security properties that matter:
authentication is required, path traversal is blocked for read / download /
view / delete, uploads stay inside the root, and debug mode is off.

## 📁 Project structure

```
File-Manager-Site/
├── app.py                 # the application (routes + path-safety layer)
├── requirements.txt
├── templates/             # index, login, text/image viewers
├── static/                # stylesheet
├── tests/
│   └── test_security.py   # traversal, auth and upload regression tests
└── .github/workflows/ci.yml
```

## ✨ Features

- Browse folders one level at a time, with size and modified date per item
- Multi-file upload
- Download a file, or a whole folder as a zip
- View text files in the browser
- Delete files and folders
- Bilingual interface (English / Hebrew)

## 📄 License

MIT — see [LICENSE](LICENSE).
