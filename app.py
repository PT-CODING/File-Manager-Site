from flask import Flask, render_template, request, redirect, url_for, send_from_directory, abort, session, flash
from werkzeug.utils import secure_filename
from functools import wraps
import os
import shutil
import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey1234'

UPLOAD_FOLDER = 'uploads'
USERNAME = 'admin'
PASSWORD = 'admin123'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- Authentication ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        if u == USERNAME and p == PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('browse'))
        else:
            flash('Username or Password incorrect')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Format file size ---
def format_size(bytes_size):
    """Convert bytes to appropriate unit (KB, MB, GB, etc.)"""
    bytes_size = float(bytes_size)
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    while bytes_size >= 1000 and unit_index < len(units) - 1:
        bytes_size /= 1000
        unit_index += 1
    return f"{bytes_size:.2f} {units[unit_index]}"

# --- Calculate directory size ---
def get_dir_size(path):
    """Calculate total size of a directory in bytes"""
    total_size = 0
    try:
        for root, dirs, files in os.walk(path):
            for name in files:
                total_size += os.path.getsize(os.path.join(root, name))
    except Exception as e:
        print(f"Error calculating size for {path}: {e}")
    return total_size

# --- List directory ---
def list_dir(path):
    items = []
    total_size_bytes = 0
    files_count = 0
    dirs_count = 0
    try:
        for root, dirs, files in os.walk(path):
            for name in dirs:
                dirs_count += 1
                full_path = os.path.join(root, name)
                mtime = os.path.getmtime(full_path)
                mtime_str = datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                rel_path = os.path.relpath(full_path, path)
                dir_size = get_dir_size(full_path)
                total_size_bytes += dir_size
                items.append({
                    'name': rel_path,
                    'is_dir': True,
                    'size': format_size(dir_size),
                    'date': mtime_str,
                    'mtime': mtime
                })
            for name in files:
                files_count += 1
                full_path = os.path.join(root, name)
                size = os.path.getsize(full_path)
                total_size_bytes += size
                mtime = os.path.getmtime(full_path)
                mtime_str = datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                rel_path = os.path.relpath(full_path, path)
                items.append({
                    'name': rel_path,
                    'is_dir': False,
                    'size': format_size(size),
                    'date': mtime_str,
                    'mtime': mtime
                })
        # Sort by modification time (newest first), directories before files
        items = sorted(items, key=lambda x: (not x['is_dir'], -x['mtime']))
    except Exception as e:
        print(f"Error listing directory {path}: {e}")
    return items, total_size_bytes, files_count, dirs_count

# --- Check if text file ---
def is_text_file(filename):
    text_extensions = ['.txt', '.py', '.md', '.json', '.csv', '.log', '.xml', '.html', '.css', '.js']
    ext = os.path.splitext(filename)[1].lower()
    return ext in text_extensions

# --- Routes ---
@app.route('/')
@login_required
def root_redirect():
    return redirect(url_for('browse'))

@app.route('/browse', defaults={'req_path': ''})
@app.route('/browse/<path:req_path>')
@login_required
def browse(req_path):
    abs_path = os.path.join(app.config['UPLOAD_FOLDER'], req_path)
    if not os.path.exists(abs_path):
        return abort(404)

    if os.path.isfile(abs_path):
        return send_from_directory(os.path.dirname(abs_path), os.path.basename(abs_path), as_attachment=True)

    files, total_size_bytes, files_count, dirs_count = list_dir(abs_path)
    parent = os.path.dirname(req_path)
    total_size = format_size(total_size_bytes)

    return render_template('index.html', files=files, current_path=req_path, parent_path=parent,
                           total_size=total_size, files_count=files_count, dirs_count=dirs_count)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    uploaded_files = request.files.getlist("files[]")
    target_path = request.form.get("path", "")
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], target_path)
    os.makedirs(save_path, exist_ok=True)

    for file in uploaded_files:
        if file.filename == '':
            continue
        file_path = os.path.join(save_path, file.filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        file.save(file_path)

    flash(f'הועלו {len(uploaded_files)} קבצים בהצלחה')
    return redirect(url_for('browse', req_path=target_path))

@app.route('/download/<path:req_path>')
@login_required
def download(req_path):
    abs_path = os.path.join(app.config['UPLOAD_FOLDER'], req_path)
    if os.path.isdir(abs_path):
        zip_path = abs_path + ".zip"
        shutil.make_archive(abs_path, 'zip', abs_path)
        return send_from_directory(os.path.dirname(zip_path), os.path.basename(zip_path), as_attachment=True)
    elif os.path.isfile(abs_path):
        return send_from_directory(os.path.dirname(abs_path), os.path.basename(abs_path), as_attachment=True)
    else:
        return abort(404)

@app.route('/delete/<path:req_path>', methods=['POST'])
@login_required
def delete(req_path):
    abs_path = os.path.join(app.config['UPLOAD_FOLDER'], req_path)
    try:
        if os.path.isdir(abs_path):
            shutil.rmtree(abs_path)
        elif os.path.isfile(abs_path):
            os.remove(abs_path)
        else:
            flash('הקובץ או התיקיה לא נמצאו')
            return redirect(url_for('browse'))
        flash('הקובץ/תיקיה נמחק בהצלחה')
    except Exception as e:
        flash(f'שגיאה במחיקה: {e}')
    parent = os.path.dirname(req_path)
    return redirect(url_for('browse', req_path=parent))

@app.route('/view/<path:req_path>')
@login_required
def view_file(req_path):
    abs_path = os.path.join(app.config['UPLOAD_FOLDER'], req_path)
    if not os.path.isfile(abs_path):
        flash("הקובץ לא נמצא")
        return redirect(url_for('browse'))

    if not is_text_file(abs_path):
        flash("סוג הקובץ אינו נתמך לתצוגה")
        return redirect(url_for('browse', req_path=os.path.dirname(req_path)))

    try:
        with open(abs_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        flash(f"שגיאה בקריאת הקובץ: {e}")
        return redirect(url_for('browse', req_path=os.path.dirname(req_path)))

    filename = os.path.basename(abs_path)
    return render_template('view_text.html', content=content, filename=filename)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000", debug=True)