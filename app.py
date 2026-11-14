"""
Digital Gaming Product Keys Store — Vercel-compatible version.

Stack: Flask + PostgreSQL (production) / SQLite (local) + Fernet encryption for stored keys.
Deployed on Vercel as serverless functions.
"""
import os, re, secrets, uuid, sqlite3
from datetime import datetime, timezone
from functools import wraps
from flask import (Flask, g, request, session, redirect, url_for, flash, abort,
                   render_template, send_from_directory, make_response)
from jinja2 import DictLoader
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

BASE = os.path.dirname(os.path.abspath(__file__))
UPLOADS = os.path.join(BASE, "uploads")
os.makedirs(UPLOADS, exist_ok=True)
MIN_TOPUP = 50
IMG_MAGIC = {b"\x89PNG": "png", b"\xff\xd8\xff": "jpg", b"RIFF": "webp"}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(32).hex()),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
)

# Get encryption key
key_enc_secret = os.environ.get("KEY_ENC_SECRET")
if not key_enc_secret:
    from cryptography.fernet import Fernet
    key_enc_secret = Fernet.generate_key().decode()
    print(f"Generated KEY_ENC_SECRET: {key_enc_secret} - Save this to your environment!")
fernet = Fernet(key_enc_secret.encode())

# Database setup: auto-detect DB_TYPE ('postgresql' or 'sqlite')
DB_TYPE = os.environ.get("DB_TYPE")
DATABASE_URL = os.environ.get("DATABASE_URL")
connection_pool = None

# If DB_TYPE is 'postgresql' or a valid remote DATABASE_URL is provided, attempt PostgreSQL
if DB_TYPE == "postgresql" or (not DB_TYPE and DATABASE_URL and not DATABASE_URL.startswith("postgresql://user:password@localhost")):
    try:
        import psycopg2
        from psycopg2 import pool
        from psycopg2.extras import RealDictCursor
        connection_pool = psycopg2.pool.SimpleConnectionPool(
            minconn=1,
            maxconn=10,
            dsn=DATABASE_URL,
            cursor_factory=RealDictCursor
        )
        DB_TYPE = "postgresql"
    except Exception as e:
        print(f"Could not connect to PostgreSQL ({e}). Using SQLite.")
        connection_pool = None
        DB_TYPE = "sqlite"
else:
    DB_TYPE = "sqlite"

DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "store.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  pw TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer', active INTEGER NOT NULL DEFAULT 1,
  balance INTEGER NOT NULL DEFAULT 0 CHECK(balance>=0), created_at TEXT);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT, image TEXT,
  price INTEGER NOT NULL CHECK(price>0), active INTEGER NOT NULL DEFAULT 1, category TEXT DEFAULT 'General', created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS keys(id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER NOT NULL REFERENCES products(id),
  key_enc BLOB NOT NULL, key_hash TEXT UNIQUE, status TEXT NOT NULL DEFAULT 'unused', order_id INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE, user_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL, price INTEGER NOT NULL, status TEXT NOT NULL, key_id INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL,
  amount INTEGER NOT NULL, ref TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS topups(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, amount INTEGER NOT NULL,
  utr TEXT UNIQUE NOT NULL, status TEXT NOT NULL DEFAULT 'pending', reviewed_by INTEGER, reviewed_at TEXT,
  reason TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER, action TEXT, target TEXT, detail TEXT, created_at TEXT);
"""

now = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")


class RowDict(dict):
    """Dictionary supporting integer indexing for SQL queries like fetchone()[0]"""
    def __getitem__(self, key):
        if isinstance(key, int):
            vals = list(self.values())
            if 0 <= key < len(vals):
                return vals[key]
        return super().__getitem__(key)


class SmartCursor:
    def __init__(self, raw_conn, is_postgres=False):
        self.raw_conn = raw_conn
        self.is_postgres = is_postgres
        self.cur = raw_conn.cursor()
        self.last_inserted_id = None

    def execute(self, sql, params=None):
        params = params or ()
        sql_stripped = sql.strip()
        is_insert = sql_stripped.upper().startswith("INSERT")

        if self.is_postgres:
            if is_insert and "RETURNING" not in sql_stripped.upper() and " INTO SETTINGS" not in sql_stripped.upper():
                try:
                    self.cur.execute(sql + " RETURNING id", params)
                    res = self.cur.fetchone()
                    if res and "id" in res:
                        self.last_inserted_id = res["id"]
                    return self
                except Exception:
                    self.raw_conn.rollback()
            self.cur.execute(sql, params)
        else:
            sql_conv = sql.replace("%s", "?")
            self.cur.execute(sql_conv, params)
            if is_insert:
                self.last_inserted_id = self.cur.lastrowid

        return self

    def fetchone(self):
        row = self.cur.fetchone()
        if row is None:
            if self.last_inserted_id is not None:
                lid = self.last_inserted_id
                self.last_inserted_id = None
                return RowDict({"id": lid})
            return None
        if isinstance(row, sqlite3.Row):
            return RowDict(dict(row))
        if isinstance(row, dict):
            return RowDict(row)
        return row

    def fetchall(self):
        rows = self.cur.fetchall()
        if not rows:
            return []
        if isinstance(rows[0], sqlite3.Row):
            return [RowDict(dict(r)) for r in rows]
        if isinstance(rows[0], dict):
            return [RowDict(r) for r in rows]
        return rows

    @property
    def rowcount(self):
        return self.cur.rowcount

    def close(self):
        try:
            self.cur.close()
        except Exception:
            pass


class SmartConnection:
    def __init__(self, raw_conn, is_postgres=False):
        self._raw = raw_conn
        self.is_postgres = is_postgres
        self._autocommit = True

    @property
    def autocommit(self):
        return getattr(self._raw, "autocommit", self._autocommit)

    @autocommit.setter
    def autocommit(self, val):
        self._autocommit = val
        if hasattr(self._raw, "autocommit"):
            try:
                self._raw.autocommit = val
            except Exception:
                pass

    def commit(self):
        self._raw.commit()

    def rollback(self):
        self._raw.rollback()

    def cursor(self):
        return self._raw.cursor()

    def close(self):
        self._raw.close()


def get_db_connection():
    """Get a database connection"""
    if DB_TYPE == "postgresql" and connection_pool:
        raw = connection_pool.getconn()
        return SmartConnection(raw, is_postgres=True)
    else:
        raw = sqlite3.connect(DB_PATH)
        raw.row_factory = sqlite3.Row
        return SmartConnection(raw, is_postgres=False)


def release_db_connection(sconn):
    """Release a database connection"""
    if not sconn:
        return
    if DB_TYPE == "postgresql" and connection_pool and sconn.is_postgres:
        connection_pool.putconn(sconn._raw)
    else:
        sconn.close()


def db():
    """Get database cursor for current request"""
    if "db_conn" not in g:
        g.db_conn = get_db_connection()
        g.db_cursor = SmartCursor(g.db_conn._raw, is_postgres=(DB_TYPE == "postgresql"))
    return g.db_cursor


@app.teardown_appcontext
def close_db(error):
    """Close database connection at end of request"""
    cursor = g.pop("db_cursor", None)
    conn = g.pop("db_conn", None)
    if cursor:
        cursor.close()
    if conn:
        release_db_connection(conn)


def init_db():
    """Initialize database schema"""
    email = os.environ.get("ADMIN_EMAIL")
    pw = os.environ.get("ADMIN_PASSWORD")

    if DB_TYPE == "postgresql":
        if not connection_pool:
            print("Cannot initialize database: no connection pool")
            return
        conn = get_db_connection()
        try:
            cur = conn._raw.cursor()
            pg_schema = SCHEMA.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY").replace("BLOB", "BYTEA")
            cur.execute(pg_schema)
            conn.commit()

            if email and pw:
                cur.execute("SELECT 1 FROM users WHERE role='admin'")
                if not cur.fetchone():
                    cur.execute(
                        "INSERT INTO users(email,name,pw,role,created_at) VALUES(%s,%s,%s,%s,%s)",
                        (email.lower(), "Admin", generate_password_hash(pw), "admin", now())
                    )
                    conn.commit()
                    print(f"Admin user created: {email}")

            cur.execute("SELECT 1 FROM settings WHERE k='store_name'")
            if not cur.fetchone():
                cur.execute("INSERT INTO settings(k,v) VALUES(%s,%s)", ("store_name", "VANTA"))
                conn.commit()
        except Exception as e:
            print(f"Error initializing database: {e}")
            conn.rollback()
        finally:
            cur.close()
            release_db_connection(conn)
    else:
        # SQLite
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.executescript(SCHEMA)
            c = conn.cursor()
            if email and pw:
                c.execute("SELECT 1 FROM users WHERE role='admin'")
                if not c.fetchone():
                    c.execute(
                        "INSERT INTO users(email,name,pw,role,created_at) VALUES(?,?,?,?,?)",
                        (email.lower(), "Admin", generate_password_hash(pw), "admin", now())
                    )
                    conn.commit()
                    print(f"Admin user created: {email}")
            c.execute("SELECT 1 FROM settings WHERE k='store_name'")
            if not c.fetchone():
                c.execute("INSERT INTO settings(k,v) VALUES(?,?)", ("store_name", "VANTA"))
                conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error initializing SQLite database: {e}")


def audit(action, target, detail=""):
    """Log admin action"""
    try:
        db().execute(
            "INSERT INTO audit(admin_id,action,target,detail,created_at) VALUES(%s,%s,%s,%s,%s)",
            (session.get("uid"), action, target, detail, now())
        )
        g.db_conn.commit()
    except Exception as e:
        print(f"Error logging audit: {e}")
        g.db_conn.rollback()


def setting(k, default=""):
    """Get setting value"""
    try:
        db().execute("SELECT v FROM settings WHERE k=%s", (k,))
        r = db().fetchone()
        if k == "store_name" and not r:
            return "VANTA"
        return r["v"] if r else default
    except Exception:
        return "VANTA" if k == "store_name" else default


def set_setting(k, v):
    """Set setting value"""
    try:
        db().execute(
            "INSERT INTO settings(k,v) VALUES(%s,%s) ON CONFLICT(k) DO UPDATE SET v=EXCLUDED.v",
            (k, v)
        )
        g.db_conn.commit()
    except Exception as e:
        print(f"Error setting value: {e}")
        g.db_conn.rollback()


# ---------- auth / security ----------
@app.before_request
def load_user():
    g.user = None
    session.setdefault("csrf", secrets.token_hex(16))
    if "uid" in session:
        try:
            db().execute("SELECT * FROM users WHERE id=%s AND active=1", (session["uid"],))
            u = db().fetchone()
            if u:
                g.user = u
            else:
                session.pop("uid", None)
        except Exception:
            session.pop("uid", None)
    if request.method == "POST":  # CSRF
        token = request.form.get("csrf", "") or request.headers.get("X-CSRFToken", "")
        expected = session.get("csrf", "")
        if not expected or not secrets.compare_digest(token, expected):
            abort(400, "Invalid or missing CSRF token. Please refresh the page.")


@app.context_processor
def ctx():
    session.setdefault("csrf", secrets.token_hex(16))
    links = []
    for line in setting("support_links").splitlines():
        if "|" in line:
            label, url = [x.strip() for x in line.split("|", 1)]
            if url.startswith(("https://", "http://")): links.append((label, url))
    return dict(
        csrf=session["csrf"],
        user=g.get("user"),
        store_name=setting("store_name", "Key Store"),
        support_links=links,
        banner=setting("banner"),
        banner_url=setting("youtube_url")
    )


@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'"
    return r


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user: return redirect(url_for("login"))
        return f(*a, **k)
    return w


def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user or g.user["role"] != "admin": abort(403)
        return f(*a, **k)
    return w


def save_image(file):
    if not file or not file.filename: return None
    head = file.read(12); file.seek(0)
    ext = next((e for m, e in IMG_MAGIC.items() if head.startswith(m)), None)
    if not ext or (ext == "webp" and head[8:12] != b"WEBP"):
        flash("Only PNG, JPG or WebP images up to 2 MB are allowed."); return None
    name = f"{uuid.uuid4().hex}.{ext}"
    file.save(os.path.join(UPLOADS, name))
    return name


@app.route("/uploads/<name>")
def uploads(name):
    return send_from_directory(UPLOADS, name)


# ---------- customer ----------
@app.route("/")
def home():
    try:
        db().execute("""SELECT p.*, (SELECT COUNT(*) FROM "keys" k WHERE k.product_id=p.id AND k.status='unused') stock
                       FROM products p WHERE p.active=1 ORDER BY p.id DESC""")
        rows = db().fetchall()

        # Group products by category
        categories = {}
        for p in rows:
            cat = p.get('category', 'General')
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(p)

        return render_template("home.html", products=rows, categories=categories)
    except Exception as e:
        print(f"Error loading home: {e}")
        return render_template("home.html", products=[], categories={})


@app.route("/product/<int:pid>")
def product(pid):
    try:
        db().execute("""SELECT p.*, (SELECT COUNT(*) FROM "keys" k WHERE k.product_id=p.id AND k.status='unused') stock
                       FROM products p WHERE p.id=%s AND p.active=1""", (pid,))
        p = db().fetchone()
        if not p: abort(404)
        return render_template("product.html", p=p)
    except Exception as e:
        print(f"Error loading product: {e}")
        abort(404)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name, email, pw = request.form["name"].strip()[:80], request.form["email"].strip().lower(), request.form["password"]
        if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(pw) < 8:
            flash("Enter a name, a valid email and a password of at least 8 characters.")
        else:
            try:
                db().execute("INSERT INTO users(email,name,pw,created_at) VALUES(%s,%s,%s,%s)",
                            (email, name, generate_password_hash(pw), now()))
                g.db_conn.commit()
                flash("Account created. Please sign in.")
                return redirect(url_for("login"))
            except Exception as e:
                print(f"Registration error: {e}")
                flash("That email is already registered.")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            db().execute("SELECT * FROM users WHERE email=%s AND active=1", (request.form["email"].strip().lower(),))
            u = db().fetchone()
            if u and check_password_hash(u["pw"], request.form["password"]):
                session["uid"] = u["id"]
                session.setdefault("csrf", secrets.token_hex(16))
                return redirect(url_for("admin_home" if u["role"] == "admin" else "home"))
            flash("Email or password is incorrect.")
        except Exception as e:
            print(f"Login error: {e}")
            flash("Error during login.")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("uid", None)
    return redirect(url_for("home"))


@app.route("/wallet", methods=["GET", "POST"])
@login_required
def wallet():
    if request.method == "POST":
        utr = request.form.get("utr", "").strip().upper()
        try: amount = int(request.form.get("amount", ""))
        except ValueError: amount = 0
        if amount < MIN_TOPUP:
            flash(f"Minimum top-up is ₹{MIN_TOPUP}.")
        elif not re.fullmatch(r"[A-Z0-9]{8,30}", utr):
            flash("Enter a valid UTR (8–30 letters or digits).")
        else:
            try:
                db().execute("INSERT INTO topups(user_id,amount,utr,created_at) VALUES(%s,%s,%s,%s)",
                            (g.user["id"], amount, utr, now()))
                g.db_conn.commit()
                flash("Request submitted. Your wallet is credited after an admin verifies the payment.")
            except Exception as e:
                print(f"Topup error: {e}")
                g.db_conn.rollback()
                flash("This UTR has already been submitted.")
        return redirect(url_for("wallet"))

    try:
        db().execute("SELECT * FROM topups WHERE user_id=%s ORDER BY id DESC", (g.user["id"],))
        tops = db().fetchall()
        db().execute("SELECT * FROM ledger WHERE user_id=%s ORDER BY id DESC LIMIT 100", (g.user["id"],))
        led = db().fetchall()
        return render_template("wallet.html", tops=tops, led=led, upi_id=setting("upi_id"), qr=setting("upi_qr"), min=MIN_TOPUP)
    except Exception as e:
        print(f"Wallet error: {e}")
        return render_template("wallet.html", tops=[], led=[], upi_id=setting("upi_id"), qr=setting("upi_qr"), min=MIN_TOPUP)


@app.route("/buy/<int:pid>", methods=["POST"])
@login_required
def buy(pid):
    try:
        g.db_conn.autocommit = False
        db().execute("SELECT * FROM products WHERE id=%s AND active=1", (pid,))
        p = db().fetchone()
        if not p: raise ValueError("This product is not available.")

        db().execute("SELECT id FROM \"keys\" WHERE product_id=%s AND status='unused' ORDER BY id LIMIT 1", (pid,))
        key = db().fetchone()
        if not key: raise ValueError("This product is out of stock.")

        db().execute("UPDATE users SET balance=balance-%s WHERE id=%s AND balance>=%s", (p["price"], g.user["id"], p["price"]))
        if db().rowcount != 1: raise ValueError("Your wallet balance is too low. Add funds first.")

        ref = "ORD-" + secrets.token_hex(5).upper()
        db().execute("INSERT INTO orders(ref,user_id,product_id,price,status,key_id,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                    (ref, g.user["id"], pid, p["price"], "completed", key["id"], now()))
        oid = db().fetchone()["id"]

        db().execute("UPDATE \"keys\" SET status='sold', order_id=%s WHERE id=%s AND status='unused'", (oid, key["id"]))
        if db().rowcount != 1: raise ValueError("Could not reserve a key. Please try again.")

        db().execute("INSERT INTO ledger(user_id,type,amount,ref,created_at) VALUES(%s,%s,%s,%s,%s)",
                    (g.user["id"], "purchase", -p["price"], ref, now()))

        g.db_conn.commit()
        flash("Purchase complete. Your key is below.")
        return redirect(url_for("order_detail", oid=oid))
    except ValueError as e:
        g.db_conn.rollback()
        flash(str(e))
    except Exception as e:
        g.db_conn.rollback()
        print(f"Purchase error: {e}")
        flash("Something went wrong. You were not charged.")
    finally:
        g.db_conn.autocommit = True
    return redirect(url_for("product", pid=pid))


@app.route("/orders")
@login_required
def orders():
    try:
        db().execute("""SELECT o.*, p.name pname FROM orders o JOIN products p ON p.id=o.product_id
                       WHERE o.user_id=%s ORDER BY o.id DESC""", (g.user["id"],))
        rows = db().fetchall()
        return render_template("orders.html", orders=rows)
    except Exception as e:
        print(f"Orders error: {e}")
        return render_template("orders.html", orders=[])


@app.route("/orders/<int:oid>")
@login_required
def order_detail(oid):
    try:
        db().execute("""SELECT o.*, p.name pname, k.key_enc FROM orders o JOIN products p ON p.id=o.product_id
                       LEFT JOIN "keys" k ON k.id=o.key_id WHERE o.id=%s""", (oid,))
        o = db().fetchone()
        if not o or (o["user_id"] != g.user["id"] and g.user["role"] != "admin"): abort(404)
        if o.get("key_enc"):
            raw_k = o["key_enc"]
            raw_bytes = raw_k.tobytes() if hasattr(raw_k, "tobytes") else bytes(raw_k)
            key = fernet.decrypt(raw_bytes).decode()
        else:
            key = None
        r = make_response(render_template("order.html", o=o, key=key))
        r.headers["Cache-Control"] = "no-store"
        return r
    except Exception as e:
        print(f"Order detail error: {e}")
        abort(404)


# ---------- admin ----------
@app.route("/admin")
@admin_required
def admin_home():
    try:
        q = lambda s: db().execute(s).fetchone()[0]
        stats = {
            "Customers": q("SELECT COUNT(*) FROM users WHERE role='customer'"),
            "Products": q("SELECT COUNT(*) FROM products"),
            "Orders": q("SELECT COUNT(*) FROM orders"),
            "Pending top-ups": q("SELECT COUNT(*) FROM topups WHERE status='pending'"),
            "Unused keys": q("SELECT COUNT(*) FROM \"keys\" WHERE status='unused'")
        }
        return render_template("admin_home.html", stats=stats,
                              customers=stats["Customers"], products=stats["Products"],
                              orders=stats["Orders"], pending_topups=stats["Pending top-ups"],
                              unused_keys=stats["Unused keys"])
    except Exception as e:
        print(f"Admin home error: {e}")
        return render_template("admin_home.html", stats={})


@app.route("/admin/products", methods=["GET", "POST"])
@admin_required
def admin_products():
    if request.method == "POST":
        pid = request.form.get("id")
        try:
            price = int(request.form["price"])
            assert price > 0
        except Exception:
            flash("Enter a valid price.")
            return redirect(url_for("admin_products"))

        img = save_image(request.files.get("image"))
        category = request.form.get("category", "General")[:50]
        vals = (request.form["name"].strip()[:120], request.form.get("description", "")[:2000], price,
                1 if request.form.get("active") else 0, category, now())

        try:
            if pid:
                db().execute("UPDATE products SET name=%s,description=%s,price=%s,active=%s,category=%s,updated_at=%s WHERE id=%s",
                            (*vals, int(pid)))
                if img:
                    db().execute("UPDATE products SET image=%s WHERE id=%s", (img, int(pid)))
                audit("product.update", f"product:{pid}", str(vals[:3]))
            else:
                db().execute("INSERT INTO products(name,description,price,active,category,created_at,updated_at,image) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                            (*vals, vals[5], img))
                audit("product.create", f"product:{db().fetchone()['id']}", vals[0])
            g.db_conn.commit()
        except Exception as e:
            print(f"Product save error: {e}")
            g.db_conn.rollback()
        return redirect(url_for("admin_products"))

    try:
        db().execute("""SELECT p.*, (SELECT COUNT(*) FROM "keys" k WHERE k.product_id=p.id AND k.status='unused') unused,
                       (SELECT COUNT(*) FROM "keys" k WHERE k.product_id=p.id AND k.status='sold') sold FROM products p""")
        rows = db().fetchall()
        return render_template("admin_products.html", products=rows)
    except Exception as e:
        print(f"Admin products error: {e}")
        return render_template("admin_products.html", products=[])


@app.route("/admin/keys", methods=["GET", "POST"])
@admin_required
def admin_keys():
    if request.method == "POST":
        pid = int(request.form["product_id"])
        added = dup = 0
        for line in request.form["keys"].splitlines():
            k = line.strip()
            if not k: continue
            h = __import__("hashlib").sha256(k.encode()).hexdigest()
            try:
                db().execute("INSERT INTO \"keys\"(product_id,key_enc,key_hash,created_at) VALUES(%s,%s,%s,%s)",
                            (pid, fernet.encrypt(k.encode()), h, now()))
                added += 1
            except:
                dup += 1
        audit("keys.add", f"product:{pid}", f"added={added} duplicates={dup}")
        g.db_conn.commit()
        flash(f"{added} key(s) added, {dup} duplicate(s) skipped.")
        return redirect(url_for("admin_keys"))

    try:
        db().execute("SELECT id,name FROM products")
        products = db().fetchall()
        db().execute("""SELECT k.id,k.status,k.order_id,p.name FROM "keys" k JOIN products p ON p.id=k.product_id
                       ORDER BY k.id DESC LIMIT 200""")
        keys = db().fetchall()
        return render_template("admin_keys.html", products=products, keys=keys)
    except Exception as e:
        print(f"Admin keys error: {e}")
        return render_template("admin_keys.html", products=[], keys=[])


@app.route("/admin/keys/<int:kid>/delete", methods=["POST"])
@admin_required
def admin_key_delete(kid):
    try:
        if db().execute("DELETE FROM \"keys\" WHERE id=%s AND status='unused'", (kid,)).rowcount:
            audit("keys.delete", f"key:{kid}")
            g.db_conn.commit()
        else:
            flash("Sold keys cannot be deleted.")
    except Exception as e:
        print(f"Key delete error: {e}")
        g.db_conn.rollback()
    return redirect(url_for("admin_keys"))


@app.route("/admin/customers")
@admin_required
def admin_customers():
    try:
        db().execute("SELECT * FROM users WHERE role='customer' ORDER BY id DESC")
        rows = db().fetchall()
        return render_template("admin_customers.html", rows=rows)
    except Exception as e:
        print(f"Admin customers error: {e}")
        return render_template("admin_customers.html", rows=[])


@app.route("/admin/customers/<int:uid>")
@admin_required
def admin_customer(uid):
    try:
        db().execute("SELECT * FROM users WHERE id=%s", (uid,))
        u = db().fetchone()
        if not u: abort(404)
        db().execute("SELECT * FROM orders WHERE user_id=%s ORDER BY id DESC", (uid,))
        orders = db().fetchall()
        db().execute("SELECT * FROM ledger WHERE user_id=%s ORDER BY id DESC", (uid,))
        led = db().fetchall()
        return render_template("admin_customer.html", c=u, orders=orders, led=led)
    except Exception as e:
        print(f"Admin customer error: {e}")
        abort(404)


@app.route("/admin/customers/<int:uid>/toggle", methods=["POST"])
@admin_required
def admin_customer_toggle(uid):
    try:
        db().execute("UPDATE users SET active=1-active WHERE id=%s AND role='customer'", (uid,))
        audit("customer.toggle", f"user:{uid}")
        g.db_conn.commit()
    except Exception as e:
        print(f"Customer toggle error: {e}")
        g.db_conn.rollback()
    return redirect(url_for("admin_customer", uid=uid))


@app.route("/admin/customers/<int:uid>/balance", methods=["POST"])
@admin_required
def admin_customer_balance(uid):
    try:
        amt = int(request.form.get("amount", 0))
        if amt != 0:
            db().execute("UPDATE users SET balance=balance+%s WHERE id=%s", (amt, uid))
            db().execute("INSERT INTO ledger(user_id,type,amount,ref,created_at) VALUES(%s,%s,%s,%s,%s)",
                        (uid, "adjustment", amt, "ADMIN_CREDIT", now()))
            audit("customer.balance", f"user:{uid}", f"amount={amt}")
            g.db_conn.commit()
            flash(f"Updated customer balance by ₹{amt}.")
    except Exception as e:
        g.db_conn.rollback()
        flash(f"Error adjusting balance: {e}")
    return redirect(url_for("admin_customer", uid=uid))


@app.route("/admin/orders")
@admin_required
def admin_orders():
    try:
        db().execute("""SELECT o.*, u.email, p.name pname FROM orders o
                       JOIN users u ON u.id=o.user_id JOIN products p ON p.id=o.product_id ORDER BY o.id DESC LIMIT 300""")
        rows = db().fetchall()
        return render_template("admin_orders.html", rows=rows)
    except Exception as e:
        print(f"Admin orders error: {e}")
        return render_template("admin_orders.html", rows=[])


@app.route("/admin/topups")
@admin_required
def admin_topups():
    try:
        db().execute("""SELECT t.*, u.email FROM topups t JOIN users u ON u.id=t.user_id
                       ORDER BY (t.status='pending') DESC, t.id DESC LIMIT 300""")
        rows = db().fetchall()
        return render_template("admin_topups.html", rows=rows)
    except Exception as e:
        print(f"Admin topups error: {e}")
        return render_template("admin_topups.html", rows=[])


@app.route("/admin/topups/<int:tid>/<action>", methods=["POST"])
@admin_required
def admin_topup_review(tid, action):
    if action not in ("approve", "reject"): abort(404)
    try:
        g.db_conn.autocommit = False
        db().execute("SELECT * FROM topups WHERE id=%s", (tid,))
        t = db().fetchone()
        if not t: abort(404)

        status = "approved" if action == "approve" else "rejected"
        db().execute("UPDATE topups SET status=%s, reviewed_by=%s, reviewed_at=%s, reason=%s WHERE id=%s AND status='pending'",
                    (status, g.user["id"], now(), request.form.get("reason", "")[:200], tid))
        if db().rowcount != 1:
            g.db_conn.rollback()
            flash("This request was already reviewed.")
            return redirect(url_for("admin_topups"))

        if action == "approve":
            db().execute("UPDATE users SET balance=balance+%s WHERE id=%s", (t["amount"], t["user_id"]))
            db().execute("INSERT INTO ledger(user_id,type,amount,ref,created_at) VALUES(%s,%s,%s,%s,%s)",
                        (t["user_id"], "topup", t["amount"], f"UTR:{t['utr']}", now()))

        audit(f"topup.{status}", f"topup:{tid}", f"user={t['user_id']} amount={t['amount']} utr={t['utr']}")
        g.db_conn.commit()
    except Exception as e:
        g.db_conn.rollback()
        print(f"Topup review error: {e}")
        raise
    finally:
        g.db_conn.autocommit = True
    return redirect(url_for("admin_topups"))


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        yt = request.form.get("youtube_url", "").strip()
        if yt and not yt.startswith("https://"):
            flash("YouTube URL must start with https://")
            return redirect(url_for("admin_settings"))

        for k in ("store_name", "upi_id", "support_links"):
            set_setting(k, request.form.get(k, "").strip()[:2000])
        set_setting("youtube_url", yt)

        for field, key in (("banner", "banner"), ("upi_qr", "upi_qr")):
            n = save_image(request.files.get(field))
            if n: set_setting(key, n)

        audit("settings.update", "settings")
        flash("Settings saved.")
        return redirect(url_for("admin_settings"))

    return render_template("admin_settings.html", s={k: setting(k) for k in
                           ("store_name", "upi_id", "youtube_url", "support_links", "banner", "upi_qr")})


@app.route("/admin/audit")
@admin_required
def admin_audit():
    try:
        db().execute("SELECT * FROM audit ORDER BY id DESC LIMIT 300")
        rows = db().fetchall()
        return render_template("admin_audit.html", rows=rows)
    except Exception as e:
        print(f"Admin audit error: {e}")
        return render_template("admin_audit.html", rows=[])


# ---------- templates ----------
BASE_T = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ store_name }}</title><style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
:root{
  --bg:#080c14;
  --bg-gradient:radial-gradient(ellipse at 50% -20%, #172554 0%, #080c14 60%, #030712 100%);
  --panel:rgba(17,24,39,0.75);
  --panel-glass:rgba(17,24,39,0.55);
  --line:rgba(56,189,248,0.18);
  --tx:#f1f5f9;
  --mut:#94a3b8;
  --acc:#00e5ff;
  --acc-gradient:linear-gradient(135deg,#00e5ff 0%,#0077fe 100%);
  --acc-glow:rgba(0,229,255,0.4);
  --bad:#ff4757;
  --bad-gradient:linear-gradient(135deg,#ff4757 0%,#e84118 100%);
  --success:#10b981;
  --warning:#f59e0b;
  --purple:#a855f7;
  --purple-gradient:linear-gradient(135deg,#c084fc 0%,#7c3aed 100%);
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:'Inter',system-ui,-apple-system,sans-serif;
  background:var(--bg);
  background-image:var(--bg-gradient);
  background-attachment:fixed;
  color:var(--tx);
  min-height:100vh;
  line-height:1.6;
  overflow-x:hidden;
  position:relative;
}
body::before{
  content:'';
  position:fixed;
  top:0;left:0;right:0;bottom:0;
  background:
    radial-gradient(circle at 15% 25%,rgba(0,229,255,0.18) 0%,transparent 40%),
    radial-gradient(circle at 85% 15%,rgba(168,85,247,0.2) 0%,transparent 45%),
    radial-gradient(circle at 50% 80%,rgba(16,185,129,0.12) 0%,transparent 40%),
    radial-gradient(circle at 90% 85%,rgba(245,158,11,0.1) 0%,transparent 35%);
  pointer-events:none;
  z-index:0;
  animation:ambientPulse 10s ease-in-out infinite alternate;
}
@keyframes ambientPulse{
  0%{opacity:0.8;transform:scale(1)}
  100%{opacity:1.2;transform:scale(1.08)}
}
body::after{
  content:'';
  position:fixed;
  top:0;left:0;right:0;bottom:0;
  background-image:
    linear-gradient(rgba(0,229,255,0.04) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,229,255,0.04) 1px,transparent 1px);
  background-size:60px 60px;
  pointer-events:none;
  z-index:0;
  animation:gridShift 25s linear infinite;
}
@keyframes gridShift{
  0%{transform:translate(0,0)}
  100%{transform:translate(60px,60px)}
}
a{color:var(--acc);text-decoration:none;transition:all 0.3s ease}
a:hover{color:#38bdf8;text-shadow:0 0 18px var(--acc-glow)}
header{
  position:sticky;
  top:0;
  z-index:100;
  padding:16px 5vw;
  display:flex;
  gap:20px;
  align-items:center;
  flex-wrap:wrap;
  background:rgba(8,12,20,0.85);
  backdrop-filter:blur(24px);
  border-bottom:1px solid rgba(0,229,255,0.2);
  box-shadow:0 8px 32px rgba(0,0,0,0.6),0 0 40px rgba(0,229,255,0.1);
  animation:headerPulse 6s ease-in-out infinite;
}
@keyframes headerPulse{
  0%,100%{box-shadow:0 8px 32px rgba(0,0,0,0.6),0 0 40px rgba(0,229,255,0.1)}
  50%{box-shadow:0 8px 32px rgba(0,0,0,0.6),0 0 70px rgba(168,85,247,0.25)}
}
.brand-title{
  font-size:1.6rem;
  font-weight:900;
  margin-right:auto;
  display:inline-flex;
  align-items:center;
  gap:10px;
  letter-spacing:-0.5px;
  background:var(--acc-gradient);
  -webkit-background-clip:text;
  -webkit-text-fill-color:transparent;
  background-clip:text;
  transition:all 0.3s ease;
}
.brand-title:hover{
  transform:scale(1.03);
  filter:drop-shadow(0 0 12px var(--acc-glow));
}
.logo-icon{
  display:inline-block;
  font-size:1.6rem;
  animation:logoSpin 4s ease-in-out infinite;
}
@keyframes logoSpin{
  0%,100%{transform:rotate(0deg) scale(1)}
  50%{transform:rotate(12deg) scale(1.15)}
}
.nav-link{
  padding:8px 18px;
  border-radius:10px;
  font-weight:600;
  font-size:0.95rem;
  border:1px solid transparent;
  transition:all 0.3s ease;
}
.nav-link:hover{
  background:rgba(0,229,255,0.12);
  border-color:rgba(0,229,255,0.3);
  transform:translateY(-2px);
  box-shadow:0 4px 15px rgba(0,229,255,0.2);
}
footer{
  border-top:1px solid rgba(255,255,255,0.08);
  margin-top:70px;
  padding:35px 5vw;
  color:var(--mut);
  text-align:center;
  background:rgba(8,12,20,0.9);
  backdrop-filter:blur(15px);
  position:relative;
  z-index:2;
}
footer a{margin:0 15px;color:var(--mut);transition:all 0.3s ease}
footer a:hover{color:var(--acc)}
main{
  position:relative;
  z-index:1;
  padding:40px 5vw;
  max-width:1250px;
  margin:auto;
  animation:mainFade 0.6s cubic-bezier(0.16,1,0.3,1);
}
@keyframes mainFade{
  from{opacity:0;transform:translateY(15px)}
  to{opacity:1;transform:translateY(0)}
}
h1,h2,h3{line-height:1.2;font-weight:800;margin-bottom:20px}
h1{
  font-size:2.8rem;
  background:linear-gradient(135deg,#ffffff 0%,#00e5ff 70%,#c084fc 100%);
  -webkit-background-clip:text;
  -webkit-text-fill-color:transparent;
  background-clip:text;
  margin-bottom:30px;
  letter-spacing:-0.5px;
}
h2{font-size:1.9rem;color:var(--tx)}
h3{font-size:1.35rem;color:var(--tx)}
.grid{
  display:grid;
  grid-template-columns:repeat(auto-fill,minmax(290px,1fr));
  gap:26px;
}
.card{
  background:var(--panel);
  backdrop-filter:blur(16px);
  border:1px solid var(--line);
  border-radius:20px;
  padding:24px;
  transition:all 0.4s cubic-bezier(0.2,0.8,0.2,1);
  position:relative;
  overflow:hidden;
  animation:cardEntrance 0.7s cubic-bezier(0.16,1,0.3,1) both;
}
@keyframes cardEntrance{
  from{opacity:0;transform:translateY(30px) scale(0.96)}
  to{opacity:1;transform:translateY(0) scale(1)}
}
.card::before{
  content:'';
  position:absolute;
  top:0;left:0;right:0;bottom:0;
  background:linear-gradient(135deg,rgba(0,229,255,0.15) 0%,rgba(168,85,247,0.12) 50%,transparent 100%);
  opacity:0;
  transition:opacity 0.4s ease;
  pointer-events:none;
}
.card:hover{
  transform:translateY(-10px) scale(1.02);
  border-color:rgba(0,229,255,0.6);
  box-shadow:
    0 20px 40px rgba(0,0,0,0.6),
    0 0 50px rgba(0,229,255,0.22),
    inset 0 0 25px rgba(0,229,255,0.06);
}
.card:hover::before{opacity:1}
.card img,.banner{
  width:100%;
  border-radius:14px;
  display:block;
  object-fit:cover;
  transition:transform 0.4s ease;
}
.card img{aspect-ratio:16/10;margin-bottom:18px}
.card:hover img{transform:scale(1.05)}
.card-placeholder-art{
  width:100%;
  aspect-ratio:16/10;
  border-radius:14px;
  background:linear-gradient(135deg,rgba(0,229,255,0.12) 0%,rgba(168,85,247,0.12) 50%,rgba(8,12,20,0.8) 100%);
  display:flex;
  align-items:center;
  justify-content:center;
  margin-bottom:18px;
  border:1px solid rgba(0,229,255,0.25);
  transition:all 0.4s ease;
}
.card:hover .card-placeholder-art{
  border-color:var(--acc);
  box-shadow:inset 0 0 30px rgba(0,229,255,0.2);
}
.controller-icon{
  font-size:3.5rem;
  display:inline-block;
  animation:floatIcon 3s ease-in-out infinite;
}
@keyframes floatIcon{
  0%,100%{transform:translateY(0) scale(1)}
  50%{transform:translateY(-8px) scale(1.08)}
}
.banner{
  max-height:320px;
  margin-bottom:35px;
  border:2px solid rgba(0,229,255,0.4);
  box-shadow:0 12px 40px rgba(0,0,0,0.5),0 0 50px rgba(0,229,255,0.2);
  animation:bannerGlow 5s ease-in-out infinite alternate;
}
@keyframes bannerGlow{
  0%{filter:drop-shadow(0 10px 20px rgba(0,229,255,0.2))}
  100%{filter:drop-shadow(0 15px 40px rgba(168,85,247,0.35))}
}
input,textarea,select{
  font:inherit;
  padding:14px 18px;
  border-radius:12px;
  border:2px solid var(--line);
  background:rgba(15,23,42,0.85);
  color:var(--tx);
  max-width:100%;
  width:100%;
  transition:all 0.3s ease;
  backdrop-filter:blur(10px);
}
input:focus,textarea:focus,select:focus{
  outline:none;
  border-color:var(--acc);
  box-shadow:0 0 25px var(--acc-glow);
  transform:translateY(-2px);
}
input::placeholder,textarea::placeholder{color:var(--mut)}
button,.btn{
  background:var(--acc-gradient);
  color:#030712;
  border:0;
  font-weight:800;
  cursor:pointer;
  text-decoration:none;
  padding:14px 30px;
  border-radius:12px;
  display:inline-flex;
  align-items:center;
  justify-content:center;
  gap:8px;
  transition:all 0.3s cubic-bezier(0.16,1,0.3,1);
  box-shadow:0 4px 18px var(--acc-glow),0 0 35px rgba(0,229,255,0.25);
  position:relative;
  overflow:hidden;
  animation:buttonPulse 3s ease-in-out infinite;
}
@keyframes buttonPulse{
  0%,100%{box-shadow:0 4px 18px var(--acc-glow),0 0 35px rgba(0,229,255,0.25)}
  50%{box-shadow:0 4px 28px var(--acc-glow),0 0 60px rgba(0,229,255,0.5)}
}
button:hover,.btn:hover{
  transform:translateY(-4px) scale(1.04);
  box-shadow:0 10px 35px var(--acc-glow),0 0 70px rgba(0,229,255,0.5);
  filter:brightness(1.1);
}
button:active,.btn:active{transform:translateY(-1px) scale(0.98)}
button.alt{
  background:rgba(255,255,255,0.05);
  color:var(--tx);
  border:2px solid rgba(255,255,255,0.2);
  box-shadow:none;
  animation:none;
}
button.alt:hover{
  border-color:var(--acc);
  background:rgba(0,229,255,0.12);
  color:var(--acc);
}
button.bad{
  background:var(--bad-gradient);
  color:#fff;
  box-shadow:0 4px 18px rgba(255,71,87,0.35);
  animation:none;
}
button.bad:hover{box-shadow:0 8px 30px rgba(255,71,87,0.55)}
form.stack>*{display:block;margin:14px 0;width:100%;max-width:480px}
form.stack label{display:block;margin-bottom:8px;font-weight:600;color:var(--tx);font-size:0.95rem}
form.inline{display:inline}
table{
  width:100%;
  border-collapse:collapse;
  display:block;
  overflow-x:auto;
  background:var(--panel);
  border-radius:14px;
  overflow:hidden;
  border:1px solid var(--line);
}
td,th{padding:18px 20px;border-bottom:1px solid rgba(255,255,255,0.06);text-align:left}
th{
  background:rgba(0,229,255,0.12);
  font-weight:700;
  color:var(--acc);
  text-transform:uppercase;
  font-size:0.85rem;
  letter-spacing:1px;
}
tr:hover td{background:rgba(0,229,255,0.06)}
.flash{
  background:linear-gradient(135deg,rgba(0,229,255,0.2) 0%,rgba(168,85,247,0.15) 100%);
  border-left:5px solid var(--acc);
  padding:18px 24px;
  margin:20px 0;
  border-radius:12px;
  backdrop-filter:blur(15px);
  box-shadow:0 8px 30px rgba(0,229,255,0.2);
  animation:flashSlide 0.5s cubic-bezier(0.16,1,0.3,1);
}
@keyframes flashSlide{
  from{opacity:0;transform:translateY(-15px) scale(0.97)}
  to{opacity:1;transform:translateY(0) scale(1)}
}
.muted{color:var(--mut)}
code.key{
  background:rgba(8,12,20,0.95);
  padding:16px 22px;
  border-radius:12px;
  display:block;
  user-select:all;
  word-break:break-all;
  font-family:'Courier New',monospace;
  font-size:1.1rem;
  font-weight:700;
  border:2px solid var(--acc);
  color:var(--acc);
  text-shadow:0 0 15px var(--acc-glow);
  box-shadow:0 0 25px rgba(0,229,255,0.25);
  animation:keyPulse 3s ease-in-out infinite;
}
@keyframes keyPulse{
  0%,100%{border-color:var(--acc);box-shadow:0 0 20px rgba(0,229,255,0.25)}
  50%{border-color:var(--purple);box-shadow:0 0 35px rgba(168,85,247,0.45)}
}
.stat-card{
  text-align:center;
  padding:32px 20px;
  transition:all 0.4s cubic-bezier(0.16,1,0.3,1);
}
.stat-card:hover{
  transform:translateY(-8px) scale(1.03);
  box-shadow:0 15px 40px rgba(0,229,255,0.25);
}
.stat-card .muted{
  font-size:0.9rem;
  text-transform:uppercase;
  letter-spacing:1px;
  margin-bottom:12px;
  font-weight:600;
}
.stat-card h2{
  font-size:3.2rem;
  background:var(--purple-gradient);
  -webkit-background-clip:text;
  -webkit-text-fill-color:transparent;
  background-clip:text;
  margin:0;
}
.status-badge{
  display:inline-block;
  padding:6px 14px;
  border-radius:20px;
  font-size:0.85rem;
  font-weight:700;
  text-transform:uppercase;
  letter-spacing:0.5px;
}
.status-completed{background:rgba(16,185,129,0.2);color:var(--success);border:1px solid rgba(16,185,129,0.4)}
.status-pending{background:rgba(245,158,11,0.2);color:var(--warning);border:1px solid rgba(245,158,11,0.4)}
.status-rejected{background:rgba(255,71,87,0.2);color:var(--bad);border:1px solid rgba(255,71,87,0.4)}
.price-tag{
  font-size:1.6rem;
  font-weight:800;
  color:var(--acc);
  text-shadow:0 0 16px var(--acc-glow);
}
.stock-indicator{
  display:inline-flex;
  align-items:center;
  gap:8px;
  padding:6px 14px;
  border-radius:20px;
  font-size:0.85rem;
  font-weight:600;
}
.stock-in{background:rgba(16,185,129,0.2);color:var(--success);border:1px solid rgba(16,185,129,0.4)}
.stock-out{background:rgba(255,71,87,0.2);color:var(--bad);border:1px solid rgba(255,71,87,0.4)}
.stock-indicator::before{
  content:'';
  width:8px;height:8px;
  border-radius:50%;
  background:currentColor;
  animation:dotPulse 1.8s ease-in-out infinite;
}
@keyframes dotPulse{
  0%,100%{transform:scale(1);opacity:1;box-shadow:0 0 0 0 currentColor}
  50%{transform:scale(1.3);opacity:0.6;box-shadow:0 0 0 8px transparent}
}
.floating-particles{
  position:fixed;
  top:0;left:0;right:0;bottom:0;
  pointer-events:none;
  z-index:0;
  overflow:hidden;
}
.particle{
  position:absolute;
  width:5px;height:5px;
  background:var(--acc);
  border-radius:50%;
  box-shadow:0 0 10px var(--acc);
  opacity:0.35;
  animation:floatParticle 16s linear infinite;
}
@keyframes floatParticle{
  0%{transform:translateY(100vh) rotate(0deg);opacity:0}
  15%{opacity:0.45}
  85%{opacity:0.45}
  100%{transform:translateY(-100vh) rotate(720deg);opacity:0}
}
.shimmer{position:relative;overflow:hidden}
.shimmer::after{
  content:'';
  position:absolute;
  top:0;left:-100%;
  width:100%;height:100%;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,0.18),transparent);
  animation:shimmer 3.5s infinite;
}
@keyframes shimmer{0%{left:-100%}100%{left:100%}}
.glow-text{
  text-shadow:0 0 12px var(--acc-glow),0 0 25px var(--acc-glow);
}
@media(max-width:768px){
  header{padding:14px 20px}
  .brand-title{font-size:1.3rem}
  main{padding:20px}
  h1{font-size:2rem}
  .grid{grid-template-columns:1fr}
  form.stack>*{max-width:100%}
}</style></head><body>
<header>
<div style="display:flex;align-items:center;gap:10px">
  <span class="logo-icon">⚡</span>
  <b><a href="/" class="brand-title">{{ store_name }}</a></b>
</div>
{% if user %}{% if user.role=='admin' %}<a href="{{ url_for('admin_home') }}" class="nav-link" style="color:var(--purple);border-color:rgba(168,85,247,0.4);background:rgba(168,85,247,0.12)">📊 Admin Portal</a>{% else %}
<a href="{{ url_for('orders') }}" class="nav-link">📦 My Orders</a>
<a href="{{ url_for('wallet') }}" class="nav-link" style="color:var(--success);background:rgba(16,185,129,0.12);border-color:rgba(16,185,129,0.3)">💰 Wallet ₹{{ user.balance }}</a>{% endif %}
<form class="inline" method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="alt" style="padding:8px 18px;font-size:0.9rem">Sign out</button></form>
{% else %}<a href="{{ url_for('login') }}" class="nav-link">Sign in</a>
<a href="{{ url_for('register') }}" class="btn" style="padding:8px 22px;font-size:0.9rem">🚀 Create Account</a>{% endif %}</header>
<div class="floating-particles">
  <div class="particle" style="left:8%;animation-delay:0s"></div>
  <div class="particle" style="left:18%;animation-delay:2.5s;background:var(--purple);box-shadow:0 0 10px var(--purple)"></div>
  <div class="particle" style="left:28%;animation-delay:5s"></div>
  <div class="particle" style="left:38%;animation-delay:1.2s"></div>
  <div class="particle" style="left:48%;animation-delay:3.8s;background:var(--success);box-shadow:0 0 10px var(--success)"></div>
  <div class="particle" style="left:58%;animation-delay:6s"></div>
  <div class="particle" style="left:68%;animation-delay:2s;background:var(--purple);box-shadow:0 0 10px var(--purple)"></div>
  <div class="particle" style="left:78%;animation-delay:4.4s"></div>
  <div class="particle" style="left:88%;animation-delay:1.8s"></div>
  <div class="particle" style="left:95%;animation-delay:3.2s;background:var(--success);box-shadow:0 0 10px var(--success)"></div>
</div>
<main>{% for m in get_flashed_messages() %}<div class="flash">⚡ {{ m }}</div>{% endfor %}{% block body %}{% endblock %}</main>
<footer>{% for l,u in support_links %}<a href="{{ u }}" rel="noopener noreferrer" target="_blank">{{ l }}</a>{% endfor %}</footer></body></html>"""

CSRF = '<input type="hidden" name="csrf" value="{{ csrf }}">'
ADMIN_NAV = ("<div style='display:flex;gap:12px;flex-wrap:wrap;margin-bottom:35px;align-items:center'>" +
    "<a href=\"/\" style=\"padding:11px 22px;background:rgba(255,255,255,0.06);border-radius:12px;border:1px solid rgba(255,255,255,0.2);color:#fff;font-weight:700;display:inline-flex;align-items:center;gap:6px;transition:all 0.3s ease\" onmouseover=\"this.style.borderColor='var(--acc)';this.style.boxShadow='0 0 15px var(--acc-glow)'\" onmouseout=\"this.style.borderColor='rgba(255,255,255,0.2)';this.style.boxShadow='none'\">🏪 Storefront</a>" +
    "".join(f'<a href="{{{{ url_for(\'{e}\') }}}}" style="padding:11px 22px;background:rgba(0,229,255,0.1);border-radius:12px;border:1px solid rgba(0,229,255,0.3);font-weight:700;transition:all 0.3s ease" onmouseover="this.style.background=\'rgba(0,229,255,0.22)\';this.style.transform=\'translateY(-2px)\';this.style.boxShadow=\'0 4px 20px var(--acc-glow)\'" onmouseout="this.style.background=\'rgba(0,229,255,0.1)\';this.style.transform=\'none\';this.style.boxShadow=\'none\'">{n}</a> ' for e, n in [
    ("admin_home", "📊 Overview"), ("admin_products", "🎮 Products"), ("admin_keys", "🔑 Keys"), ("admin_customers", "👥 Customers"),
    ("admin_orders", "📦 Orders"), ("admin_topups", "💰 Top-ups"), ("admin_settings", "⚙️ Settings"), ("admin_audit", "📜 Audit")]) + "</div>")


def page(body, admin=False):
    return "{% extends 'base.html' %}{% block body %}" + (ADMIN_NAV if admin else "") + body + "{% endblock %}"


def table(heads, row):
    return ("<table><tr>" + "".join(f"<th>{h}</th>" for h in heads) + "</tr>{% for r in rows %}<tr>" + row + "</tr>{% endfor %}</table>")


T = {
 "base.html": BASE_T,
 "home.html": page("""{% if banner %}{% if banner_url %}<a href="{{ banner_url }}" target="_blank" rel="noopener noreferrer">{% endif %}
<img class="banner shimmer" src="{{ url_for('uploads', name=banner) }}" alt="Store banner">{% if banner_url %}</a>{% endif %}{% endif %}
<div class="card shimmer" style="text-align:center;padding:60px 40px;margin-bottom:45px;background:linear-gradient(135deg,rgba(0,229,255,0.12) 0%,rgba(168,85,247,0.15) 100%);border:2px solid rgba(0,229,255,0.35);border-radius:24px">
<h1 class="glow-text" style="font-size:3.6rem;margin-bottom:18px">🎮 Free Fire Store</h1>
<p style="font-size:1.35rem;color:var(--mut);margin-bottom:30px;max-width:700px;margin-left:auto;margin-right:auto">Instant digital delivery of Free Fire game items at unbeatable prices.</p>
<div style="display:flex;gap:25px;justify-content:center;flex-wrap:wrap">
<div style="text-align:center;padding:18px 25px;background:rgba(0,229,255,0.08);border-radius:14px;border:1px solid rgba(0,229,255,0.2)"><div style="font-size:2.4rem;margin-bottom:6px">🔒</div><div style="font-weight:700;color:var(--acc)">Encrypted Vault</div></div>
<div style="text-align:center;padding:18px 25px;background:rgba(168,85,247,0.08);border-radius:14px;border:1px solid rgba(168,85,247,0.2)"><div style="font-size:2.4rem;margin-bottom:6px">⚡</div><div style="font-weight:700;color:var(--purple)">Instant Delivery</div></div>
<div style="text-align:center;padding:18px 25px;background:rgba(16,185,129,0.08);border-radius:14px;border:1px solid rgba(16,185,129,0.2)"><div style="font-size:2.4rem;margin-bottom:6px">💎</div><div style="font-weight:700;color:var(--success)">100% Genuine</div></div>
</div>
</div>
{% if not products %}<p class="muted" style="text-align:center;font-size:1.2rem;padding:40px">No products available yet. Check back soon!</p>{% endif %}
{% for category_name, category_products in categories.items() %}
<div style="margin-bottom:50px">
<h2 class="glow-text" style="font-size:2.2rem;margin-bottom:25px;padding-bottom:15px;border-bottom:2px solid rgba(0,229,255,0.3)">🏷️ {{ category_name }}</h2>
<div class="grid">
{% for p in category_products %}<a class="card shimmer" href="{{ url_for('product', pid=p.id) }}" style="text-decoration:none;color:inherit">
{% if p.image %}<img src="{{ url_for('uploads', name=p.image) }}" alt="{{ p.name }}">{% else %}
<div class="card-placeholder-art"><span class="controller-icon">🎮</span></div>{% endif %}
<h3 style="font-size:1.3rem;margin-bottom:10px">{{ p.name }}</h3>
<p class="muted" style="font-size:0.95rem;margin-bottom:18px;min-height:42px">{{ p.description or 'Official game product activation key.' }}</p>
<div style="display:flex;justify-content:space-between;align-items:center;margin-top:auto">
<span class="price-tag">₹{{ p.price }}</span>
<span class="stock-indicator {{ 'stock-in' if p.stock else 'stock-out' }}">{{ p.stock ~ ' In Stock' if p.stock else 'Out of Stock' }}</span>
</div>
<div style="margin-top:16px;text-align:center;background:rgba(0,229,255,0.12);padding:10px;border-radius:10px;font-weight:700;color:var(--acc);border:1px solid rgba(0,229,255,0.25)">View Details →</div></a>{% endfor %}
</div>
</div>
{% endfor %}"""),
 "product.html": page("""<div class="card shimmer" style="max-width:760px;margin:0 auto">{% if p.image %}<img src="{{ url_for('uploads', name=p.image) }}" alt="" style="max-width:100%;margin-bottom:30px;border-radius:18px;box-shadow:0 12px 40px rgba(0,229,255,0.25)">{% else %}
<div class="card-placeholder-art" style="aspect-ratio:16/8"><span class="controller-icon" style="font-size:5rem">🎮</span></div>{% endif %}
<div style="display:inline-block;padding:8px 20px;background:rgba(168,85,247,0.2);border-radius:20px;border:1px solid rgba(168,85,247,0.4);margin-bottom:15px;font-weight:700;color:var(--purple);font-size:0.95rem">🏷️ {{ p.category or 'General' }}</div>
<h1 class="glow-text" style="font-size:2.8rem">{{ p.name }}</h1><p style="color:var(--mut);font-size:1.2rem;line-height:1.8;margin:20px 0">{{ p.description }}</p>
<div style="margin:30px 0;padding:30px;background:linear-gradient(135deg,rgba(0,229,255,0.12) 0%,rgba(168,85,247,0.12) 100%);border-radius:18px;border:2px solid rgba(0,229,255,0.35);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:15px">
<div>
<div style="font-size:1rem;color:var(--mut);margin-bottom:4px">Instant Price</div>
<div class="price-tag glow-text" style="font-size:3.5rem">₹{{ p.price }}</div>
</div>
<div>
<span class="stock-indicator {{ 'stock-in' if p.stock else 'stock-out' }}" style="font-size:1.1rem;padding:10px 20px">{{ p.stock ~ ' Keys Available' if p.stock else 'Out of Stock' }}</span>
</div>
</div>
{% if p.stock %}{% if user %}<form method="post" action="{{ url_for('buy', pid=p.id) }}">""" + CSRF + """<button style="font-size:1.25rem;padding:20px 48px;width:100%">⚡ Buy with Wallet (₹{{ user.balance }} Available)</button></form>
{% else %}<a class="btn" href="{{ url_for('login') }}" style="font-size:1.2rem;padding:18px 44px;display:block;text-align:center">🔐 Sign in to Buy</a>{% endif %}{% else %}<p class="muted" style="background:rgba(255,71,87,0.2);padding:22px;border-radius:14px;color:var(--bad);font-size:1.2rem;text-align:center;border:1px solid rgba(255,71,87,0.35)">❌ Out of Stock — New keys arriving soon!</p>{% endif %}</div>"""),
 "register.html": page("""<div class="card shimmer" style="max-width:520px;margin:30px auto;text-align:center;padding:45px"><h1 class="glow-text" style="font-size:2.6rem">✨ Create Account</h1>
<p style="color:var(--mut);margin-bottom:30px;font-size:1.1rem">Join VANTA Store and unlock instant game keys.</p>
<form class="stack" method="post" style="max-width:100%">""" + CSRF + """<label>👤 Full Name<input name="name" placeholder="John Gamer" required></label>
<label>📧 Email Address<input name="email" type="email" placeholder="you@domain.com" required></label><label>🔒 Password (min 8 chars)<input name="password" type="password" minlength="8" placeholder="••••••••" required></label><button style="font-size:1.15rem;padding:16px 34px;width:100%">🚀 Create Free Account</button></form></div>"""),
 "login.html": page("""<div class="card shimmer" style="max-width:520px;margin:30px auto;text-align:center;padding:45px"><h1 class="glow-text" style="font-size:2.6rem">🔐 Sign In</h1>
<p style="color:var(--mut);margin-bottom:30px;font-size:1.1rem">Welcome back! Sign in to access your wallet and orders.</p>
<form class="stack" method="post" style="max-width:100%">""" + CSRF + """<label>📧 Email Address<input name="email" type="email" placeholder="you@domain.com" required></label>
<label>🔒 Password<input name="password" type="password" placeholder="••••••••" required></label><button style="font-size:1.15rem;padding:16px 34px;width:100%">🎮 Sign In</button></form></div>"""),
 "wallet.html": page("""<div class="card shimmer" style="max-width:760px;margin:0 auto;text-align:center;padding:50px;background:linear-gradient(135deg,rgba(0,229,255,0.18) 0%,rgba(168,85,247,0.18) 100%);border:2px solid rgba(0,229,255,0.4);border-radius:24px"><h1 class="glow-text" style="font-size:2.6rem">💰 Wallet Balance</h1><div class="price-tag glow-text" style="font-size:5.5rem;margin:25px 0">₹{{ user.balance }}</div></div>
<div class="card shimmer" style="max-width:760px;margin:40px auto;border-radius:20px"><h2 style="font-size:2rem">➕ Add Funds via UPI</h2>
<p style="color:var(--mut);margin-bottom:25px;font-size:1.1rem">Scan QR or send UPI payment, then submit the 12-digit UTR reference number below.</p>
{% if qr %}<img src="{{ url_for('uploads', name=qr) }}" alt="UPI QR code" style="max-width:280px;border-radius:18px;margin:25px auto;display:block;box-shadow:0 12px 40px rgba(0,229,255,0.25);border:2px solid rgba(0,229,255,0.3)">{% endif %}
{% if upi_id %}<p style="background:rgba(0,229,255,0.14);padding:16px 26px;border-radius:14px;display:inline-block;font-size:1.15rem;border:2px solid rgba(0,229,255,0.35);margin-bottom:20px">💳 UPI ID: <b style="color:var(--acc)">{{ upi_id }}</b></p>{% endif %}
<form class="stack" method="post">""" + CSRF + """<label>💰 Amount Paid (₹)<input name="amount" type="number" min="{{ min }}" placeholder="Min ₹{{ min }}" required></label>
<label>🔢 12-Digit UTR / Transaction Reference<input name="utr" placeholder="e.g. 332812984512" required></label><button style="font-size:1.15rem;padding:16px 36px">✅ Submit for Instant Verification</button></form></div>
<h2 class="glow-text" style="font-size:2rem;margin-top:40px">📋 Top-up Requests</h2>""" + table(["📅 Date", "💰 Amount", "🔢 UTR", "📊 Status", "📝 Admin Note"], "<td>{{ r.created_at }}</td><td>₹{{ r.amount }}</td><td>{{ r.utr }}</td><td><span class=\"status-badge status-{{ r.status }}\">{{ r.status|capitalize }}</span></td><td>{{ r.reason or '-' }}</td>").replace("rows", "tops") + """
<h2 class="glow-text" style="font-size:2rem;margin-top:40px">📊 Transaction Ledger</h2>""" + table(["📅 Date", "📝 Type", "💰 Amount", "🔗 Reference"], "<td>{{ r.created_at }}</td><td>{{ r.type }}</td><td>₹{{ r.amount }}</td><td>{{ r.ref }}</td>").replace("rows", "led")),
 "orders.html": page("<h1 class=\"glow-text\" style=\"font-size:2.8rem\">📦 My Purchased Orders</h1>" + table(["📋 Order Ref", "🎮 Product", "💰 Paid", "📅 Date", "📊 Status", "⚡ Action"],
   "<td>{{ r.ref }}</td><td><b>{{ r.pname }}</b></td><td>₹{{ r.price }}</td><td>{{ r.created_at }}</td><td><span class=\"status-badge status-{{ r.status }}\">{{ r.status }}</span></td><td><a href=\"{{ url_for('order_detail', oid=r.id) }}\" class=\"btn\" style=\"padding:8px 18px;font-size:0.9rem\">🔑 Reveal Key</a></td>").replace("rows", "orders")),
 "order.html": page("""<div class="card shimmer" style="max-width:760px;margin:0 auto;border-radius:22px"><h1 class="glow-text" style="font-size:2.6rem">🎮 Order {{ o.ref }}</h1>
<p style="color:var(--mut);margin:25px 0;font-size:1.15rem">Game: <b style="color:var(--tx)">{{ o.pname }}</b> · Amount: <span class="price-tag">₹{{ o.price }}</span> · Date: {{ o.created_at }} · <span class="status-badge status-{{ o.status }}">{{ o.status }}</span></p>
{% if key %}
<div style="background:rgba(8,12,20,0.85);border:2px solid var(--acc);border-radius:18px;padding:28px;margin-top:30px;box-shadow:0 0 35px rgba(0,229,255,0.25)">
<p style="margin-bottom:14px;font-weight:800;font-size:1.25rem;color:var(--acc);display:flex;align-items:center;gap:10px">🔑 <span>YOUR GAME LICENSE KEY:</span></p>
<div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
<code class="key" id="licenseKey" style="flex:1;min-width:220px;font-size:1.15rem;letter-spacing:1px">{{ key }}</code>
<button type="button" onclick="navigator.clipboard.writeText('{{ key }}');this.innerHTML='✅ Copied!';this.style.background='var(--success)';setTimeout(()=>{this.innerHTML='📋 Copy Key';this.style.background='var(--acc-gradient)'},2500)" style="padding:16px 24px;white-space:nowrap;font-size:1rem">📋 Copy Key</button>
</div>
<p style="margin-top:18px;color:var(--mut);font-size:0.95rem">🔒 Instant delivery verified. Redeem this key directly on Steam, Epic Games, or the designated platform.</p>
</div>
{% endif %}</div>"""),
 "admin_home.html": page('<div class="card shimmer" style="text-align:center;padding:55px 30px;margin-bottom:40px;background:linear-gradient(135deg,rgba(168,85,247,0.18) 0%,rgba(0,229,255,0.18) 100%);border:2px solid rgba(168,85,247,0.45);border-radius:24px"><h1 class="glow-text" style="font-size:3.2rem">📊 Admin Dashboard</h1><p style="color:var(--mut);font-size:1.25rem;margin-top:12px">Store management, key inventory, customer accounts & financial control.</p></div><div class="grid"><a href="{{ url_for(\'admin_customers\') }}" style="text-decoration:none;color:inherit"><div class="card stat-card shimmer" style="background:linear-gradient(135deg,rgba(0,229,255,0.14) 0%,rgba(0,229,255,0.04) 100%);cursor:pointer"><div class="controller-icon" style="font-size:3.2rem;margin-bottom:12px">👥</div><div class="muted">Customers</div><h2 class="glow-text">{{ customers }}</h2><div style="margin-top:12px;font-size:0.9rem;color:var(--acc);font-weight:700">Manage Customers →</div></div></a><a href="{{ url_for(\'admin_products\') }}" style="text-decoration:none;color:inherit"><div class="card stat-card shimmer" style="background:linear-gradient(135deg,rgba(168,85,247,0.14) 0%,rgba(168,85,247,0.04) 100%);cursor:pointer"><div class="controller-icon" style="font-size:3.2rem;margin-bottom:12px">🎮</div><div class="muted">Products</div><h2 class="glow-text">{{ products }}</h2><div style="margin-top:12px;font-size:0.9rem;color:var(--purple);font-weight:700">Edit Catalog →</div></div></a><a href="{{ url_for(\'admin_orders\') }}" style="text-decoration:none;color:inherit"><div class="card stat-card shimmer" style="background:linear-gradient(135deg,rgba(16,185,129,0.14) 0%,rgba(16,185,129,0.04) 100%);cursor:pointer"><div class="controller-icon" style="font-size:3.2rem;margin-bottom:12px">📦</div><div class="muted">Orders</div><h2 class="glow-text">{{ orders }}</h2><div style="margin-top:12px;font-size:0.9rem;color:var(--success);font-weight:700">View Orders →</div></div></a><a href="{{ url_for(\'admin_topups\') }}" style="text-decoration:none;color:inherit"><div class="card stat-card shimmer" style="background:linear-gradient(135deg,rgba(245,158,11,0.14) 0%,rgba(245,158,11,0.04) 100%);cursor:pointer"><div class="controller-icon" style="font-size:3.2rem;margin-bottom:12px">💰</div><div class="muted">Pending Top-ups</div><h2 class="glow-text">{{ pending_topups }}</h2><div style="margin-top:12px;font-size:0.9rem;color:var(--warning);font-weight:700">Review Requests →</div></div></a><a href="{{ url_for(\'admin_keys\') }}" style="text-decoration:none;color:inherit"><div class="card stat-card shimmer" style="background:linear-gradient(135deg,rgba(255,71,87,0.14) 0%,rgba(255,71,87,0.04) 100%);cursor:pointer"><div class="controller-icon" style="font-size:3.2rem;margin-bottom:12px">🔑</div><div class="muted">Unused Keys</div><h2 class="glow-text">{{ unused_keys }}</h2><div style="margin-top:12px;font-size:0.9rem;color:var(--bad);font-weight:700">Stock Inventory →</div></div></a></div>', True),
 "admin_products.html": page("""<h1 class="glow-text" style="font-size:2.8rem">🎮 Products Management</h1><div class="card shimmer"><h3 style="font-size:1.6rem;margin-bottom:20px">➕ Add New Game Product</h3><form class="stack" method="post" enctype="multipart/form-data">""" + CSRF + """
<label>📝 Product Title<input name="name" placeholder="e.g. GTA V Premium Edition" required></label><label>📄 Description<textarea name="description" placeholder="Product details..." rows="3"></textarea></label><label>💰 Price (₹)<input name="price" type="number" min="1" placeholder="999" required></label>
<label>🏷️ Category<select name="category"><option value="General">General</option><option value="Headshot Zone">Headshot Zone</option><option value="Health">Health</option><option value="Diamonds">Diamonds</option><option value="Skins">Skins</option><option value="Weapons">Weapons</option><option value="Characters">Characters</option><option value="Battle Pass">Battle Pass</option></select></label>
<label>🖼️ Cover Image<input type="file" name="image" accept="image/png,image/jpeg,image/webp"></label><label style="display:flex;align-items:center;gap:10px;font-weight:600"><input type="checkbox" name="active" checked style="width:auto"> ✅ Active in Store</label><button>📦 Add Product</button></form></div>
{% for p in products %}<div class="card shimmer" style="margin-top:28px"><h3 style="font-size:1.5rem;margin-bottom:20px">✏️ Edit: {{ p.name }}</h3><form class="stack" method="post" enctype="multipart/form-data">""" + CSRF + """<input type="hidden" name="id" value="{{ p.id }}">
<label>📝 Product Title<input name="name" value="{{ p.name }}" required></label><label>📄 Description<textarea name="description" rows="3">{{ p.description }}</textarea></label><label>💰 Price (₹)<input name="price" type="number" min="1" value="{{ p.price }}"></label>
<label>🏷️ Category<select name="category"><option value="General" {{ 'selected' if p.category=='General' }}>General</option><option value="Headshot Zone" {{ 'selected' if p.category=='Headshot Zone' }}>Headshot Zone</option><option value="Health" {{ 'selected' if p.category=='Health' }}>Health</option><option value="Diamonds" {{ 'selected' if p.category=='Diamonds' }}>Diamonds</option><option value="Skins" {{ 'selected' if p.category=='Skins' }}>Skins</option><option value="Weapons" {{ 'selected' if p.category=='Weapons' }}>Weapons</option><option value="Characters" {{ 'selected' if p.category=='Characters' }}>Characters</option><option value="Battle Pass" {{ 'selected' if p.category=='Battle Pass' }}>Battle Pass</option></select></label>
<label>🖼️ Change Cover Image<input type="file" name="image" accept="image/png,image/jpeg,image/webp"></label><label style="display:flex;align-items:center;gap:10px;font-weight:600"><input type="checkbox" name="active" {{ 'checked' if p.active }} style="width:auto"> ✅ Active in Store</label>
<div style="margin-top:16px;padding:16px;background:rgba(0,229,255,0.15);border-radius:12px;border:1px solid rgba(0,229,255,0.35)"><span class="muted" style="font-size:1.1rem">📊 <b>{{ p.unused }}</b> unused keys · <b>{{ p.sold }}</b> sold</span></div><button style="margin-top:16px">💾 Save Changes</button></form></div>{% endfor %}""", True),
 "admin_keys.html": page("""<h1 class="glow-text" style="font-size:2.8rem">🔑 Game Keys Inventory</h1><div class="card shimmer" style="max-width:680px;margin-bottom:35px"><h3 style="font-size:1.6rem;margin-bottom:20px">➕ Bulk Import Keys</h3><form class="stack" method="post">""" + CSRF + """<label>🎮 Select Game Product<select name="product_id">{% for p in products %}<option value="{{ p.id }}">{{ p.name }}</option>{% endfor %}</select></label>
<label>🔑 Paste License Keys (one per line)<textarea name="keys" rows="8" placeholder="XXXX-XXXX-XXXX-XXXX&#10;YYYY-YYYY-YYYY-YYYY" required></textarea></label><button>📥 Import & Encrypt Keys</button></form></div>
<table><tr><th>🆔 ID</th><th>🎮 Product</th><th>📊 Status</th><th>📦 Order</th><th>⚡ Action</th></tr>{% for k in keys %}<tr><td>{{ k.id }}</td><td>{{ k.name }}</td><td><span class="status-badge status-{{ k.status }}">{{ k.status }}</span></td><td>{{ k.order_id or '-' }}</td>
<td>{% if k.status=='unused' %}<form class="inline" method="post" action="{{ url_for('admin_key_delete', kid=k.id) }}">""" + CSRF + """<button class="bad" style="padding:8px 16px;font-size:0.85rem">🗑️ Delete</button></form>{% else %}<span class="muted">Sold</span>{% endif %}</td></tr>{% endfor %}</table>""", True),
 "admin_customers.html": page("<h1 class=\"glow-text\" style=\"font-size:2.8rem\">👥 Registered Customers</h1>" + table(["👤 Customer Name", "📧 Email Address", "💰 Balance", "✅ Status", "⚡ Action"],
   "<td>{{ r.name }}</td><td>{{ r.email }}</td><td><span class=\"price-tag\">₹{{ r.balance }}</span></td><td><span class=\"status-badge {{ 'status-completed' if r.active else 'status-rejected' }}\">{{ 'Active' if r.active else 'Disabled' }}</span></td><td><a href=\"{{ url_for('admin_customer', uid=r.id) }}\" class=\"btn\" style=\"padding:8px 18px;font-size:0.9rem\">👁️ View Profile</a></td>"), True),
 "admin_customer.html": page("""<div class="card shimmer" style="max-width:850px;margin:0 auto;border-radius:24px"><h1 class="glow-text" style="font-size:2.6rem">👤 {{ c.name }}</h1><p class="muted" style="font-size:1.2rem">{{ c.email }}</p>
<p style="margin:25px 0"><span class="price-tag glow-text" style="font-size:2.8rem">💰 Current Balance: ₹{{ c.balance }}</span></p>
<div style="display:flex;gap:18px;flex-wrap:wrap;align-items:center;padding:24px;background:rgba(255,255,255,0.04);border-radius:16px;border:1px solid rgba(255,255,255,0.1)">
<form method="post" action="{{ url_for('admin_customer_toggle', uid=c.id) }}">""" + CSRF + """<button class="{{ 'bad' if c.active else 'alt' }}" style="padding:12px 24px">{{ '🚫 Disable Account' if c.active else '✅ Enable Account' }}</button></form>
<form class="inline" method="post" action="{{ url_for('admin_customer_balance', uid=c.id) }}" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">""" + CSRF + """<input name="amount" type="number" placeholder="Add ₹ (e.g. 500)" style="width:180px;padding:12px;border-radius:10px" required> <button style="padding:12px 24px">💳 Credit Balance</button></form>
</div>
</div>
<h2 class="glow-text" style="font-size:2rem;margin-top:40px">📦 Order History</h2>""" + table(["📋 Order Ref", "💰 Amount", "📅 Date", "📊 Status"], "<td><a href=\"{{ url_for('order_detail', oid=r.id) }}\">{{ r.ref }}</a></td><td>₹{{ r.price }}</td><td>{{ r.created_at }}</td><td><span class=\"status-badge status-{{ r.status }}\">{{ r.status }}</span></td>").replace("rows", "orders") + """
<h2 class="glow-text" style="font-size:2rem;margin-top:40px">📊 Financial Ledger</h2>""" + table(["📅 Date", "📝 Type", "💰 Amount", "🔗 Ref"], "<td>{{ r.created_at }}</td><td>{{ r.type }}</td><td>₹{{ r.amount }}</td><td>{{ r.ref }}</td>").replace("rows", "led"), True),
 "admin_orders.html": page("<h1 class=\"glow-text\" style=\"font-size:2.8rem\">📦 All Customer Orders</h1>" + table(["📋 Order Ref", "👤 Customer", "🎮 Game Product", "💰 Amount", "📅 Date", "📊 Status"],
   "<td><a href=\"{{ url_for('order_detail', oid=r.id) }}\" style=\"font-weight:700\">{{ r.ref }}</a></td><td>{{ r.email }}</td><td>{{ r.pname }}</td><td><span class=\"price-tag\">₹{{ r.price }}</span></td><td>{{ r.created_at }}</td><td><span class=\"status-badge status-{{ r.status }}\">{{ r.status }}</span></td>"), True),
 "admin_topups.html": page("<h1 class=\"glow-text\" style=\"font-size:2.8rem\">💰 UPI Top-up Requests</h1><p class='muted' style='background:rgba(245,158,11,0.15);padding:22px;border-radius:14px;border-left:5px solid var(--warning);font-size:1.15rem;margin-bottom:30px'>⚠️ Confirm receipt in your UPI / banking app before approving requests.</p>" + table(
   ["👤 Customer", "💰 Amount", "🔢 UTR Reference", "📅 Submitted", "📊 Status", "⚡ Verification Action"],
   "<td>{{ r.email }}</td><td><span class=\"price-tag\">₹{{ r.amount }}</span></td><td><b>{{ r.utr }}</b></td><td>{{ r.created_at }}</td><td><span class=\"status-badge status-{{ r.status }}\">{{ r.status }}</span></td><td>{% if r.status=='pending' %}"
   "<form class=\"inline\" method=\"post\" action=\"{{ url_for('admin_topup_review', tid=r.id, action='approve') }}\">" + CSRF + "<button style='padding:9px 18px;font-size:0.9rem'>✅ Approve & Credit</button></form> "
   "<form class=\"inline\" method=\"post\" action=\"{{ url_for('admin_topup_review', tid=r.id, action='reject') }}\">" + CSRF + "<input name=\"reason\" placeholder=\"Rejection reason\" style='padding:9px 12px;font-size:0.9rem;width:160px;display:inline-block'><button class=\"bad\" style='padding:9px 18px;font-size:0.9rem'>❌ Reject</button></form>{% else %}{{ r.reason or '-' }}{% endif %}</td>"), True),
 "admin_settings.html": page("""<h1 class="glow-text" style="font-size:2.8rem">⚙️ Store Settings</h1><div class="card shimmer" style="max-width:680px;margin:0 auto;border-radius:22px"><form class="stack" method="post" enctype="multipart/form-data">""" + CSRF + """
<label>🏪 Store Brand Name<input name="store_name" value="{{ s.store_name }}" placeholder="VANTA Game Keys"></label>
{% if s.banner %}<div style="margin:10px 0"><p class="muted" style="margin-bottom:6px">Current Banner:</p><img src="{{ url_for('uploads', name=s.banner) }}" style="max-height:100px;border-radius:10px;border:1px solid rgba(0,229,255,0.3)"></div>{% endif %}
<label>🖼️ Store Banner Image<input type="file" name="banner" accept="image/png,image/jpeg,image/webp"></label>
<label>🔗 Banner Click URL (e.g. YouTube promo)<input name="youtube_url" value="{{ s.youtube_url }}" placeholder="https://youtube.com/..."></label>
<label>💳 UPI ID (for Customer Top-ups)<input name="upi_id" value="{{ s.upi_id }}" placeholder="yourname@upi"></label>
{% if s.upi_qr %}<div style="margin:10px 0"><p class="muted" style="margin-bottom:6px">Current UPI QR:</p><img src="{{ url_for('uploads', name=s.upi_qr) }}" style="max-height:100px;border-radius:10px;border:1px solid rgba(0,229,255,0.3)"></div>{% endif %}
<label>📱 UPI QR Code Image<input type="file" name="upi_qr" accept="image/png,image/jpeg,image/webp"></label>
<label>🔗 Support Links (one per line: Label|https://url)<textarea name="support_links" rows="4" placeholder="Discord|https://discord.gg/...&#10;Telegram|https://t.me/...">{{ s.support_links }}</textarea></label><button style="margin-top:10px">💾 Save Store Settings</button></form></div>""", True),
 "admin_audit.html": page("<h1 class=\"glow-text\" style=\"font-size:2.8rem\">📜 Security Audit Log</h1>" + table(["🕐 Timestamp", "👤 Admin ID", "⚡ Action", "🎯 Target", "📝 Detail Log"],
   "<td>{{ r.created_at }}</td><td>{{ r.admin_id or 'System' }}</td><td><span style=\"color:var(--acc);font-weight:700\">{{ r.action }}</span></td><td>{{ r.target }}</td><td>{{ r.detail }}</td>"), True),
}
app.jinja_loader = DictLoader(T)


# Initialize database on first request
@app.before_request
def ensure_db_initialized():
    if not hasattr(app, 'db_initialized'):
        init_db()
        app.db_initialized = True


if __name__ == "__main__":
    init_db()
    app.run(debug=False, port=5000)
