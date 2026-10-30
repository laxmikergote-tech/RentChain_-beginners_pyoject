from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import date, datetime
import sqlite3, hashlib, json, os

app = Flask(__name__)
app.secret_key = os.environ.get("RENTCHAIN_SECRET", "change-this-secret-key-for-local-development")
DB_PATH = os.path.join(os.path.dirname(__file__), "rentchain.db")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('landlord','tenant')),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS agreements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            landlord_id INTEGER NOT NULL REFERENCES users(id),
            tenant_id INTEGER REFERENCES users(id),
            tenant_name TEXT NOT NULL,
            tenant_email TEXT NOT NULL,
            property_address TEXT NOT NULL,
            monthly_rent REAL NOT NULL,
            deposit REAL NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            terms TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            document_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agreement_id INTEGER NOT NULL REFERENCES agreements(id),
            event_type TEXT NOT NULL,
            event_data TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            block_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rent_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agreement_id INTEGER NOT NULL REFERENCES agreements(id),
            amount REAL NOT NULL,
            payment_month TEXT NOT NULL,
            note TEXT,
            recorded_by INTEGER NOT NULL REFERENCES users(id),
            created_at TEXT NOT NULL
        );
        """)

def add_ledger_event(con, agreement_id, event_type, event_data):
    previous = con.execute("SELECT block_hash FROM ledger ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = previous["block_hash"] if previous else "GENESIS"
    timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    payload = json.dumps({
        "agreement_id": agreement_id, "event_type": event_type,
        "event_data": event_data, "previous_hash": prev_hash, "created_at": timestamp
    }, sort_keys=True, separators=(",", ":"))
    block_hash = sha256(payload)
    con.execute(
        "INSERT INTO ledger (agreement_id,event_type,event_data,previous_hash,block_hash,created_at) VALUES (?,?,?,?,?,?)",
        (agreement_id, event_type, event_data, prev_hash, block_hash, timestamp)
    )

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def current_user():
    if "user_id" not in session:
        return None
    with db() as con:
        return con.execute("SELECT id,name,email,role FROM users WHERE id=?", (session["user_id"],)).fetchone()

@app.context_processor
def inject_user():
    return {"current_user": current_user()}

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        if not name or not email or len(password) < 8 or role not in ("landlord", "tenant"):
            flash("Enter all details. Password must contain at least 8 characters.", "danger")
            return render_template("register.html")
        try:
            with db() as con:
                con.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                            (name, email, generate_password_hash(password), role, datetime.utcnow().isoformat()))
            flash("Account created. You can now log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That email is already registered.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        flash("Email or password is incorrect.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    with db() as con:
        if user["role"] == "landlord":
            agreements = con.execute("""
                SELECT a.*, t.name AS linked_tenant_name FROM agreements a
                LEFT JOIN users t ON a.tenant_id=t.id
                WHERE a.landlord_id=? ORDER BY a.id DESC
            """, (user["id"],)).fetchall()
        else:
            agreements = con.execute("""
                SELECT a.*, l.name AS landlord_name FROM agreements a
                JOIN users l ON a.landlord_id=l.id
                WHERE a.tenant_id=? OR lower(a.tenant_email)=? ORDER BY a.id DESC
            """, (user["id"], user["email"].lower())).fetchall()
        payments = con.execute("""
            SELECT p.*, a.property_address FROM rent_payments p
            JOIN agreements a ON p.agreement_id=a.id
            WHERE a.landlord_id=? OR a.tenant_id=? ORDER BY p.id DESC LIMIT 8
        """, (user["id"], user["id"])).fetchall()
        ledger_count = con.execute("SELECT COUNT(*) AS n FROM ledger").fetchone()["n"]
    return render_template("dashboard.html", agreements=agreements, payments=payments, ledger_count=ledger_count)

@app.route("/agreements/new", methods=["GET", "POST"])
@login_required
def new_agreement():
    user = current_user()
    if user["role"] != "landlord":
        abort(403)
    if request.method == "POST":
        tenant_email = request.form.get("tenant_email", "").strip().lower()
        tenant_name = request.form.get("tenant_name", "").strip()
        address = request.form.get("property_address", "").strip()
        terms = request.form.get("terms", "").strip()
        start = request.form.get("start_date", "")
        end = request.form.get("end_date", "")
        try:
            rent = float(request.form.get("monthly_rent", ""))
            deposit = float(request.form.get("deposit", ""))
            if rent <= 0 or deposit < 0:
                raise ValueError()
            if not all([tenant_email, tenant_name, address, terms, start, end]) or end < start:
                raise ValueError()
        except ValueError:
            flash("Please enter valid details. Rent must be positive and end date must not be before start date.", "danger")
            return render_template("new_agreement.html")
        with db() as con:
            tenant = con.execute("SELECT id FROM users WHERE email=? AND role='tenant'", (tenant_email,)).fetchone()
            canonical = json.dumps({
                "landlord_id": user["id"], "tenant_email": tenant_email, "tenant_name": tenant_name,
                "property_address": address, "monthly_rent": rent, "deposit": deposit,
                "start_date": start, "end_date": end, "terms": terms
            }, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            digest = sha256(canonical)
            cur = con.execute("""
                INSERT INTO agreements(landlord_id,tenant_id,tenant_name,tenant_email,property_address,
                monthly_rent,deposit,start_date,end_date,terms,status,document_hash,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (user["id"], tenant["id"] if tenant else None, tenant_name, tenant_email, address,
                  rent, deposit, start, end, terms, "Pending", digest, datetime.utcnow().isoformat()))
            agreement_id = cur.lastrowid
            add_ledger_event(con, agreement_id, "AGREEMENT_CREATED", digest)
        flash("Agreement created and recorded in the demo ledger.", "success")
        return redirect(url_for("agreement_detail", agreement_id=agreement_id))
    return render_template("new_agreement.html")

@app.route("/agreements/<int:agreement_id>")
@login_required
def agreement_detail(agreement_id):
    user = current_user()
    with db() as con:
        agreement = con.execute("""
            SELECT a.*, l.name AS landlord_name FROM agreements a
            JOIN users l ON a.landlord_id=l.id WHERE a.id=?
        """, (agreement_id,)).fetchone()
        if not agreement:
            abort(404)
        if not (user["id"] == agreement["landlord_id"] or
                user["id"] == agreement["tenant_id"] or
                user["email"].lower() == agreement["tenant_email"].lower()):
            abort(403)
        payments = con.execute("SELECT * FROM rent_payments WHERE agreement_id=? ORDER BY id DESC",
                               (agreement_id,)).fetchall()
        events = con.execute("SELECT * FROM ledger WHERE agreement_id=? ORDER BY id DESC",
                             (agreement_id,)).fetchall()
    return render_template("agreement_detail.html", agreement=agreement, payments=payments, events=events)

@app.route("/agreements/<int:agreement_id>/status", methods=["POST"])
@login_required
def update_status(agreement_id):
    user = current_user()
    new_status = request.form.get("status")
    if new_status not in ("Pending", "Accepted", "Rejected"):
        abort(400)
    with db() as con:
        a = con.execute("SELECT * FROM agreements WHERE id=?", (agreement_id,)).fetchone()
        if not a:
            abort(404)
        if user["role"] != "tenant" or user["email"].lower() != a["tenant_email"].lower():
            abort(403)
        con.execute("UPDATE agreements SET status=? WHERE id=?", (new_status, agreement_id))
        add_ledger_event(con, agreement_id, "STATUS_CHANGED", new_status)
    flash("Agreement status updated.", "success")
    return redirect(url_for("agreement_detail", agreement_id=agreement_id))

@app.route("/agreements/<int:agreement_id>/payment", methods=["POST"])
@login_required
def add_payment(agreement_id):
    user = current_user()
    try:
        amount = float(request.form.get("amount", ""))
        month = request.form.get("payment_month", "").strip()
        note = request.form.get("note", "").strip()
        if amount <= 0 or len(month) != 7 or month[4] != "-":
            raise ValueError()
    except ValueError:
        flash("Enter a valid positive amount and month in YYYY-MM format.", "danger")
        return redirect(url_for("agreement_detail", agreement_id=agreement_id))
    with db() as con:
        a = con.execute("SELECT * FROM agreements WHERE id=?", (agreement_id,)).fetchone()
        if not a:
            abort(404)
        if user["id"] not in (a["landlord_id"], a["tenant_id"]) and user["email"].lower() != a["tenant_email"].lower():
            abort(403)
        cur = con.execute("""INSERT INTO rent_payments(agreement_id,amount,payment_month,note,recorded_by,created_at)
            VALUES(?,?,?,?,?,?)""", (agreement_id, amount, month, note, user["id"], datetime.utcnow().isoformat()))
        add_ledger_event(con, agreement_id, "RENT_PAYMENT_RECORDED",
                         json.dumps({"payment_id": cur.lastrowid, "amount": amount, "month": month}))
    flash("Payment record added. This is a record, not a payment gateway transaction.", "success")
    return redirect(url_for("agreement_detail", agreement_id=agreement_id))

@app.route("/verify", methods=["GET", "POST"])
@login_required
def verify():
    result = None
    if request.method == "POST":
        try:
            agreement_id = int(request.form.get("agreement_id", ""))
        except ValueError:
            flash("Enter a valid agreement ID.", "danger")
            return render_template("verify.html", result=None)
        user = current_user()
        with db() as con:
            a = con.execute("SELECT * FROM agreements WHERE id=?", (agreement_id,)).fetchone()
            if not a:
                flash("Agreement not found.", "danger")
            elif user["id"] not in (a["landlord_id"], a["tenant_id"]) and user["email"].lower() != a["tenant_email"].lower():
                abort(403)
            else:
                canonical = json.dumps({
                    "landlord_id": a["landlord_id"], "tenant_email": a["tenant_email"],
                    "tenant_name": a["tenant_name"], "property_address": a["property_address"],
                    "monthly_rent": a["monthly_rent"], "deposit": a["deposit"],
                    "start_date": a["start_date"], "end_date": a["end_date"], "terms": a["terms"]
                }, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                computed = sha256(canonical)
                ledger = con.execute("SELECT * FROM ledger WHERE agreement_id=? AND event_type='AGREEMENT_CREATED' ORDER BY id LIMIT 1",
                                     (agreement_id,)).fetchone()
                result = {"agreement_id": agreement_id, "matches": computed == a["document_hash"],
                          "hash": computed, "recorded_hash": a["document_hash"],
                          "ledger_recorded": bool(ledger and ledger["event_data"] == a["document_hash"])}
    return render_template("verify.html", result=result)

@app.route("/ledger")
@login_required
def ledger():
    user = current_user()
    with db() as con:
        rows = con.execute("""
            SELECT le.* FROM ledger le JOIN agreements a ON le.agreement_id=a.id
            WHERE a.landlord_id=? OR a.tenant_id=? OR lower(a.tenant_email)=?
            ORDER BY le.id DESC LIMIT 100
        """, (user["id"], user["id"], user["email"].lower())).fetchall()
    return render_template("ledger.html", events=rows)

@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="You do not have permission to view this page."), 403

@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="The page or agreement was not found."), 404

init_db()

if __name__ == "__main__":
    app.run(debug=True)
