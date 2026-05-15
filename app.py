from __future__ import annotations

import csv
import io
import os
import sqlite3
from datetime import date, datetime, timedelta
from functools import wraps
from pathlib import Path

import qrcode
from flask import (
    Flask, abort, flash, g, make_response, redirect,
    render_template, request, send_from_directory, session, url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ─── ENVIRONMENT DETECTION ────────────────────────────────────────────────────
IS_VERCEL = os.getenv("VERCEL") == "1" or os.getenv("VERCEL_ENV") is not None
IS_PROD   = os.getenv("FLASK_ENV", "development") == "production" or IS_VERCEL

# ─── PATHS ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent

# On Vercel, only /tmp is writable. Use it for DB + QR codes.
if IS_VERCEL:
    WRITABLE_DIR = Path("/tmp")
    DB_PATH = WRITABLE_DIR / "database.db"
    QR_DIR  = WRITABLE_DIR / "qrs"
else:
    WRITABLE_DIR = BASE_DIR
    DB_PATH = BASE_DIR / "database.db"
    QR_DIR  = BASE_DIR / "static" / "qrs"

STATIC_DIR = BASE_DIR / "static"

# ─── CONFIG ───────────────────────────────────────────────────────────────────
QR_MAX_AGE = int(os.getenv("QR_MAX_AGE", 86400))   # 24 hours default

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config.update(
    SECRET_KEY                = os.getenv("SECRET_KEY", "CHANGE-THIS-SECRET-IN-PRODUCTION"),
    DATABASE                  = str(DB_PATH),
    SESSION_COOKIE_HTTPONLY   = True,
    SESSION_COOKIE_SAMESITE   = "Lax",
    SESSION_COOKIE_SECURE     = IS_PROD,
    PERMANENT_SESSION_LIFETIME= timedelta(hours=12),
    MAX_CONTENT_LENGTH        = 2 * 1024 * 1024,
)

# ─── LIMITER ──────────────────────────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://",
)

# ─── SERIALIZER (timed tokens) ────────────────────────────────────────────────
serializer = URLSafeTimedSerializer(
    app.config["SECRET_KEY"], salt="qr-attendance-v2"
)


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════════════════════

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        # Ensure DB is initialised (important on Vercel where /tmp resets)
        if not DB_PATH.exists():
            init_db()
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        # WAL mode does not work well on Vercel's ephemeral /tmp — use default
        if not IS_VERCEL:
            conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def query_db(sql: str, params: tuple = (), one: bool = False):
    cur = get_db().execute(sql, params)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows


def execute_db(sql: str, params: tuple = ()):
    conn = get_db()
    cur  = conn.execute(sql, params)
    conn.commit()
    return cur


def init_db() -> None:
    # Create writable dirs safely
    try:
        QR_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT    NOT NULL,
            email     TEXT    NOT NULL UNIQUE,
            password  TEXT    NOT NULL,
            role      TEXT    NOT NULL DEFAULT 'student',
            created_at TEXT   NOT NULL DEFAULT (DATE('now'))
        );

        CREATE TABLE IF NOT EXISTS attendance (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER NOT NULL,
            date      TEXT    NOT NULL,
            time      TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_att_user_date
            ON attendance(user_id, date);
        CREATE INDEX IF NOT EXISTS idx_att_date
            ON attendance(date);
        CREATE INDEX IF NOT EXISTS idx_att_user
            ON attendance(user_id);
    """)
    conn.commit()
    conn.close()


# Initialise DB on import (works for both local + Vercel cold starts)
init_db()


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS & DECORATORS
# ══════════════════════════════════════════════════════════════════════════════

def is_valid_email(email: str) -> bool:
    return bool(email) and "@" in email and "." in email.split("@")[-1]


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def role_required(role: str):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if session.get("role") != role:
                flash("Access denied.", "danger")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapper
    return decorator


def build_qr_token(user_id: int) -> str:
    return serializer.dumps({"uid": user_id})


def parse_qr_token(token: str) -> int:
    data = serializer.loads(token, max_age=QR_MAX_AGE)
    return int(data["uid"])


def mark_attendance(user_id: int) -> tuple[bool, str]:
    user = query_db("SELECT id, name FROM users WHERE id = ?", (user_id,), one=True)
    if not user:
        return False, "User not found."
    today = date.today().isoformat()
    now   = datetime.now().strftime("%H:%M:%S")
    try:
        execute_db(
            "INSERT INTO attendance (user_id, date, time) VALUES (?, ?, ?)",
            (user_id, today, now),
        )
        return True, f"Attendance marked for {user['name']} at {now}."
    except sqlite3.IntegrityError:
        return False, f"Attendance already recorded for {user['name']} today."


def get_attendance_summary(user_id: int) -> dict:
    records = query_db(
        "SELECT date FROM attendance WHERE user_id = ? ORDER BY date ASC",
        (user_id,),
    )
    total = len(records)
    first_date = records[0]["date"] if records else date.today().isoformat()

    start = datetime.strptime(first_date, "%Y-%m-%d").date()
    end   = date.today()
    working_days = sum(
        1 for n in range((end - start).days + 1)
        if (start + timedelta(days=n)).weekday() < 6
    ) if total else 0

    pct = round((total / working_days * 100) if working_days else 0, 1)
    return {
        "total":        total,
        "working_days": working_days,
        "percentage":   pct,
        "status":       "Good" if pct >= 75 else ("Low" if pct >= 50 else "Critical"),
    }


@app.context_processor
def inject_globals():
    return {"today": date.today().isoformat(), "now": datetime.now()}


# ══════════════════════════════════════════════════════════════════════════════
# QR IMAGE SERVING (Vercel-safe)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/qrs/<path:filename>")
def serve_qr(filename: str):
    """Serve QR images from the writable directory (/tmp on Vercel)."""
    return send_from_directory(str(QR_DIR), filename)


# ══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(
            url_for("admin_dashboard" if session["role"] == "admin" else "user_dashboard")
        )
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name     = request.form.get("name", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        errors = []
        if not name or not email or not password:
            errors.append("All fields are required.")
        elif not is_valid_email(email):
            errors.append("Enter a valid email address.")
        elif len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        elif password != confirm:
            errors.append("Passwords do not match.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html")

        try:
            execute_db(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                (name, email, generate_password_hash(password)),
            )
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That email is already registered.", "warning")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "danger")
            return render_template("login.html")

        user = query_db("SELECT * FROM users WHERE email = ?", (email,), one=True)
        if user and check_password_hash(user["password"], password):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["role"]    = user["role"]
            session["name"]    = user["name"]
            flash(f"Welcome back, {user['name']}!", "success")
            return redirect(
                url_for("admin_dashboard" if user["role"] == "admin" else "user_dashboard")
            )
        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/admin")
@login_required
@role_required("admin")
def admin_dashboard():
    stats = {
        "student_count": query_db(
            "SELECT COUNT(*) AS c FROM users WHERE role='student'", one=True
        )["c"],
        "attendance_count": query_db(
            "SELECT COUNT(*) AS c FROM attendance", one=True
        )["c"],
        "today_count": query_db(
            "SELECT COUNT(*) AS c FROM attendance WHERE date=?",
            (date.today().isoformat(),), one=True,
        )["c"],
        "week_count": query_db(
            "SELECT COUNT(*) AS c FROM attendance WHERE date >= ?",
            ((date.today() - timedelta(days=7)).isoformat(),), one=True,
        )["c"],
    }

    users = query_db("""
        SELECT u.id, u.name, u.email, u.role, u.created_at,
               COUNT(a.id) AS total_attendance
        FROM users u
        LEFT JOIN attendance a ON a.user_id = u.id
        GROUP BY u.id
        ORDER BY u.name ASC
    """)

    date_from = request.args.get("from", "")
    date_to   = request.args.get("to", "")
    search    = request.args.get("q", "").strip()

    sql    = "SELECT a.id, u.name, u.email, a.date, a.time FROM attendance a JOIN users u ON u.id = a.user_id WHERE 1=1"
    params: list = []

    if date_from:
        sql += " AND a.date >= ?"; params.append(date_from)
    if date_to:
        sql += " AND a.date <= ?"; params.append(date_to)
    if search:
        sql += " AND (u.name LIKE ? OR u.email LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    sql += " ORDER BY a.date DESC, a.time DESC LIMIT 200"

    attendance = query_db(sql, tuple(params))

    qr_user_id  = request.args.get("qr", type=int)
    qr_image_url = qr_user = None
    if qr_user_id:
        qr_file = QR_DIR / f"qr_{qr_user_id}.png"
        if qr_file.exists():
            # Use our custom /qrs/<file> route instead of /static/
            qr_image_url = url_for("serve_qr", filename=f"qr_{qr_user_id}.png")
            qr_user = query_db("SELECT * FROM users WHERE id=?", (qr_user_id,), one=True)

    return render_template(
        "dashboard_admin.html",
        users=users, attendance=attendance, stats=stats,
        qr_image_url=qr_image_url, qr_user=qr_user,
        date_from=date_from, date_to=date_to, search=search,
    )


@app.route("/admin/generate_qr/<int:user_id>")
@login_required
@role_required("admin")
def generate_qr(user_id: int):
    user = query_db("SELECT * FROM users WHERE id=?", (user_id,), one=True)
    if not user:
        abort(404)

    # Ensure writable QR dir exists (re-create on every cold start in /tmp)
    QR_DIR.mkdir(parents=True, exist_ok=True)

    token    = build_qr_token(user_id)
    mark_url = request.url_root.rstrip("/") + url_for("mark_token", token=token)
    qr_path  = QR_DIR / f"qr_{user_id}.png"

    img = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    img.add_data(mark_url)
    img.make(fit=True)
    qr_img = img.make_image(fill_color="#1a1a2e", back_color="white")
    qr_img.save(str(qr_path))

    flash(f"Fresh QR code generated for {user['name']}.", "success")
    return redirect(url_for("admin_dashboard", qr=user_id))


@app.route("/admin/edit/<int:user_id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def edit_user(user_id: int):
    user = query_db("SELECT * FROM users WHERE id=?", (user_id,), one=True)
    if not user:
        abort(404)

    if request.method == "POST":
        name         = request.form.get("name", "").strip()
        email        = request.form.get("email", "").strip().lower()
        role         = request.form.get("role", "student")
        new_password = request.form.get("new_password", "")

        errors = []
        if not name or not email:
            errors.append("Name and email are required.")
        elif not is_valid_email(email):
            errors.append("Invalid email address.")
        if role not in ("student", "admin"):
            errors.append("Invalid role.")
        if new_password and len(new_password) < 8:
            errors.append("New password must be at least 8 characters.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("edit_user.html", user=user)

        try:
            if new_password:
                execute_db(
                    "UPDATE users SET name=?, email=?, role=?, password=? WHERE id=?",
                    (name, email, role, generate_password_hash(new_password), user_id),
                )
            else:
                execute_db(
                    "UPDATE users SET name=?, email=?, role=? WHERE id=?",
                    (name, email, role, user_id),
                )
            flash(f"User {name} updated successfully.", "success")
            return redirect(url_for("admin_dashboard"))
        except sqlite3.IntegrityError:
            flash("That email is already in use.", "warning")

    return render_template("edit_user.html", user=user)


@app.route("/admin/delete/<int:user_id>", methods=["POST"])
@login_required
@role_required("admin")
def delete_user(user_id: int):
    if user_id == session["user_id"]:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin_dashboard"))
    user = query_db("SELECT name FROM users WHERE id=?", (user_id,), one=True)
    if not user:
        abort(404)
    execute_db("DELETE FROM users WHERE id=?", (user_id,))
    try:
        (QR_DIR / f"qr_{user_id}.png").unlink(missing_ok=True)
    except OSError:
        pass
    flash(f"User '{user['name']}' and all their records have been deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/export")
@login_required
@role_required("admin")
def export_csv():
    date_from = request.args.get("from", "")
    date_to   = request.args.get("to", "")
    search    = request.args.get("q", "").strip()

    sql    = "SELECT u.name, u.email, a.date, a.time FROM attendance a JOIN users u ON u.id = a.user_id WHERE 1=1"
    params: list = []
    if date_from:
        sql += " AND a.date >= ?"; params.append(date_from)
    if date_to:
        sql += " AND a.date <= ?"; params.append(date_to)
    if search:
        sql += " AND (u.name LIKE ? OR u.email LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    sql += " ORDER BY a.date DESC, a.time DESC"

    records = query_db(sql, tuple(params))
    output  = io.StringIO()
    writer  = csv.writer(output)
    writer.writerow(["Name", "Email", "Date", "Time"])
    for r in records:
        writer.writerow([r["name"], r["email"], r["date"], r["time"]])

    resp = make_response(output.getvalue())
    resp.headers["Content-Type"]        = "text/csv"
    resp.headers["Content-Disposition"] = f"attachment; filename=attendance_{date.today()}.csv"
    return resp


@app.route("/admin/scanner")
@login_required
@role_required("admin")
def scanner():
    return render_template("scanner.html")


@app.route("/api/mark", methods=["POST"])
@login_required
@role_required("admin")
@limiter.limit("120 per minute")
def api_mark():
    data  = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    if not token:
        return {"success": False, "message": "No token provided."}, 400
    try:
        user_id = parse_qr_token(token)
    except SignatureExpired:
        return {"success": False, "message": "QR code has expired. Generate a fresh one."}, 400
    except (BadSignature, KeyError, ValueError, TypeError):
        return {"success": False, "message": "Invalid QR code."}, 400

    success, message = mark_attendance(user_id)
    return {"success": success, "message": message}


# ══════════════════════════════════════════════════════════════════════════════
# STUDENT ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/user")
@login_required
@role_required("student")
def user_dashboard():
    uid     = session["user_id"]
    records = query_db(
        "SELECT date, time FROM attendance WHERE user_id=? ORDER BY date DESC",
        (uid,),
    )
    today_marked  = query_db(
        "SELECT id FROM attendance WHERE user_id=? AND date=?",
        (uid, date.today().isoformat()), one=True,
    )
    summary       = get_attendance_summary(uid)
    present_dates = {r["date"] for r in records}

    return render_template(
        "dashboard_user.html",
        records=records,
        today_marked=bool(today_marked),
        summary=summary,
        present_dates=present_dates,
    )


# ══════════════════════════════════════════════════════════════════════════════
# QR MARK ROUTES (public — token-secured)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/mark/token/<token>")
@limiter.limit("30 per minute")
def mark_token(token: str):
    try:
        user_id = parse_qr_token(token)
    except SignatureExpired:
        return render_template(
            "mark_result.html", success=False,
            message="This QR code has expired. Ask your admin to regenerate it.",
        )
    except (BadSignature, KeyError, ValueError, TypeError):
        return render_template(
            "mark_result.html", success=False,
            message="Invalid QR code. Please use the original code provided by your admin.",
        )
    success, message = mark_attendance(user_id)
    return render_template("mark_result.html", success=success, message=message)


# ══════════════════════════════════════════════════════════════════════════════
# CLI COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

@app.cli.command("create-admin")
def create_admin_cmd():
    import getpass
    print("── Create Admin User ──────────────────")
    name    = input("Name  : ").strip()
    email   = input("Email : ").strip().lower()
    pwd     = getpass.getpass("Password (≥8 chars): ")
    confirm = getpass.getpass("Confirm password   : ")
    if pwd != confirm:
        print("[✗] Passwords do not match."); return
    if len(pwd) < 8:
        print("[✗] Password too short."); return
    with app.app_context():
        try:
            execute_db(
                "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'admin')",
                (name, email, generate_password_hash(pwd)),
            )
            print(f"[✓] Admin '{name}' ({email}) created successfully.")
        except sqlite3.IntegrityError:
            print("[✗] That email is already registered.")


@app.cli.command("reset-db")
def reset_db_cmd():
    confirm = input("This will DELETE all data. Type YES to continue: ")
    if confirm == "YES":
        if DB_PATH.exists():
            DB_PATH.unlink()
        init_db()
        print("[✓] Database reset complete.")
    else:
        print("Aborted.")


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", host="0.0.0.0", port=5000)