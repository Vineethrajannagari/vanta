"""
Digital Gaming Product Keys Store — single-file reference implementation.

Stack: Flask + SQLite (stdlib) + Fernet encryption for stored keys.
Run:
    pip install flask cryptography
    export SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
    export KEY_ENC_SECRET="$(python -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')"
    export ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='choose-a-strong-one'
    python keys_store.py            # http://127.0.0.1:5000
Production: run behind HTTPS (gunicorn + nginx) and set SESSION_COOKIE_SECURE=1.
"""
import os, re, secrets, sqlite3, uuid
from datetime import datetime, timezone
from functools import wraps
from flask import (Flask, g, request, session, redirect, url_for, flash, abort,
                   render_template, send_from_directory, make_response)
from jinja2 import DictLoader
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "store.db"))
UPLOADS = os.path.join(BASE, "uploads")
os.makedirs(UPLOADS, exist_ok=True)
MIN_TOPUP = 50
IMG_MAGIC = {b"\x89PNG": "png", b"\xff\xd8\xff": "jpg", b"RIFF": "webp"}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
)
fernet = Fernet(os.environ["KEY_ENC_SECRET"].encode())

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  pw TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer', active INTEGER NOT NULL DEFAULT 1,
  balance INTEGER NOT NULL DEFAULT 0 CHECK(balance>=0), created_at TEXT);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT, image TEXT,
  price INTEGER NOT NULL CHECK(price>0), active INTEGER NOT NULL DEFAULT 1, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS keys(id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL REFERENCES products(id),
  key_enc BLOB NOT NULL, key_hash TEXT UNIQUE, status TEXT NOT NULL DEFAULT 'unused', order_id INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, ref TEXT UNIQUE, user_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL, price INTEGER NOT NULL, status TEXT NOT NULL, key_id INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, type TEXT NOT NULL,
  amount INTEGER NOT NULL, ref TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS topups(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, amount INTEGER NOT NULL,
  utr TEXT UNIQUE NOT NULL, status TEXT NOT NULL DEFAULT 'pending', reviewed_by INTEGER, reviewed_at TEXT,
  reason TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, admin_id INTEGER, action TEXT, target TEXT, detail TEXT, created_at TEXT);
"""

now = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, isolation_level=None)  # manual transactions
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    c = sqlite3.connect(DB_PATH)
    c.executescript(SCHEMA)
    email, pw = os.environ.get("ADMIN_EMAIL"), os.environ.get("ADMIN_PASSWORD")
    if email and pw and not c.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        c.execute("INSERT INTO users(email,name,pw,role,created_at) VALUES(?,?,?,?,?)",
                  (email.lower(), "Admin", generate_password_hash(pw), "admin", now()))
    # Set default store name to VANTA
    if not c.execute("SELECT 1 FROM settings WHERE k='store_name'").fetchone():
        c.execute("INSERT INTO settings(k,v) VALUES(?,?)", ("store_name", "VANTA"))
    c.commit(); c.close()


def audit(action, target, detail=""):
    db().execute("INSERT INTO audit(admin_id,action,target,detail,created_at) VALUES(?,?,?,?,?)",
                 (session.get("uid"), action, target, detail, now()))


def setting(k, default=""):
    r = db().execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    # Default store name to VANTA
    if k == "store_name" and not r:
        return "VANTA"
    return r["v"] if r else default


def set_setting(k, v):
    db().execute("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))


# ---------- auth / security ----------
@app.before_request
def load_user():
    g.user = None
    if "uid" in session:
        u = db().execute("SELECT * FROM users WHERE id=? AND active=1", (session["uid"],)).fetchone()
        if u: g.user = u
        else: session.clear()
    if request.method == "POST":  # CSRF
        if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
            abort(400, "Invalid CSRF token")


@app.context_processor
def ctx():
    session.setdefault("csrf", secrets.token_hex(16))
    links = []
    for line in setting("support_links").splitlines():
        if "|" in line:
            label, url = [x.strip() for x in line.split("|", 1)]
            if url.startswith(("https://", "http://")): links.append((label, url))
    return dict(csrf=session["csrf"], user=g.get("user"), store_name=setting("store_name", "Key Store"),
                support_links=links, banner=setting("banner"), banner_url=setting("youtube_url"))


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
    rows = db().execute("""SELECT p.*, (SELECT COUNT(*) FROM keys k WHERE k.product_id=p.id AND k.status='unused') stock
                           FROM products p WHERE p.active=1 ORDER BY p.id DESC""").fetchall()
    return render_template("home.html", products=rows)


@app.route("/product/<int:pid>")
def product(pid):
    p = db().execute("""SELECT p.*, (SELECT COUNT(*) FROM keys k WHERE k.product_id=p.id AND k.status='unused') stock
                        FROM products p WHERE p.id=? AND p.active=1""", (pid,)).fetchone() or abort(404)
    return render_template("product.html", p=p)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name, email, pw = request.form["name"].strip()[:80], request.form["email"].strip().lower(), request.form["password"]
        if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(pw) < 8:
            flash("Enter a name, a valid email and a password of at least 8 characters.")
        else:
            try:
                db().execute("INSERT INTO users(email,name,pw,created_at) VALUES(?,?,?,?)",
                             (email, name, generate_password_hash(pw), now()))
                flash("Account created. Please sign in."); return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That email is already registered.")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE email=? AND active=1", (request.form["email"].strip().lower(),)).fetchone()
        if u and check_password_hash(u["pw"], request.form["password"]):
            session.clear(); session["uid"] = u["id"]; session["csrf"] = secrets.token_hex(16)
            return redirect(url_for("admin_home" if u["role"] == "admin" else "home"))
        flash("Email or password is incorrect.")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear(); return redirect(url_for("home"))


@app.route("/wallet", methods=["GET", "POST"])
@login_required
def wallet():
    d = db()
    if request.method == "POST":
        utr = request.form.get("utr", "").strip().upper()
        try: amount = int(request.form.get("amount", ""))
        except ValueError: amount = 0
        if amount < MIN_TOPUP: flash(f"Minimum top-up is ₹{MIN_TOPUP}.")
        elif not re.fullmatch(r"[A-Z0-9]{8,30}", utr): flash("Enter a valid UTR (8–30 letters or digits).")
        else:
            try:
                d.execute("INSERT INTO topups(user_id,amount,utr,created_at) VALUES(?,?,?,?)", (g.user["id"], amount, utr, now()))
                flash("Request submitted. Your wallet is credited after an admin verifies the payment.")
            except sqlite3.IntegrityError:
                flash("This UTR has already been submitted.")
        return redirect(url_for("wallet"))
    tops = d.execute("SELECT * FROM topups WHERE user_id=? ORDER BY id DESC", (g.user["id"],)).fetchall()
    led = d.execute("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 100", (g.user["id"],)).fetchall()
    return render_template("wallet.html", tops=tops, led=led, upi_id=setting("upi_id"), qr=setting("upi_qr"), min=MIN_TOPUP)


@app.route("/buy/<int:pid>", methods=["POST"])
@login_required
def buy(pid):
    d = db()
    try:
        d.execute("BEGIN IMMEDIATE")  # serialises writers: no double-sale, no half-charges
        p = d.execute("SELECT * FROM products WHERE id=? AND active=1", (pid,)).fetchone()
        if not p: raise ValueError("This product is not available.")
        key = d.execute("SELECT id FROM keys WHERE product_id=? AND status='unused' ORDER BY id LIMIT 1", (pid,)).fetchone()
        if not key: raise ValueError("This product is out of stock.")
        cur = d.execute("UPDATE users SET balance=balance-? WHERE id=? AND balance>=?", (p["price"], g.user["id"], p["price"]))
        if cur.rowcount != 1: raise ValueError("Your wallet balance is too low. Add funds first.")
        ref = "ORD-" + secrets.token_hex(5).upper()
        oid = d.execute("INSERT INTO orders(ref,user_id,product_id,price,status,key_id,created_at) VALUES(?,?,?,?,?,?,?)",
                        (ref, g.user["id"], pid, p["price"], "completed", key["id"], now())).lastrowid
        if d.execute("UPDATE keys SET status='sold', order_id=? WHERE id=? AND status='unused'", (oid, key["id"])).rowcount != 1:
            raise ValueError("Could not reserve a key. Please try again.")
        d.execute("INSERT INTO ledger(user_id,type,amount,ref,created_at) VALUES(?,?,?,?,?)",
                  (g.user["id"], "purchase", -p["price"], ref, now()))
        d.execute("COMMIT")
        flash("Purchase complete. Your key is below.")
        return redirect(url_for("order_detail", oid=oid))
    except ValueError as e:
        d.execute("ROLLBACK"); flash(str(e))
    except Exception:
        d.execute("ROLLBACK"); flash("Something went wrong. You were not charged.")
    return redirect(url_for("product", pid=pid))


@app.route("/orders")
@login_required
def orders():
    rows = db().execute("""SELECT o.*, p.name pname FROM orders o JOIN products p ON p.id=o.product_id
                           WHERE o.user_id=? ORDER BY o.id DESC""", (g.user["id"],)).fetchall()
    return render_template("orders.html", orders=rows)


@app.route("/orders/<int:oid>")
@login_required
def order_detail(oid):
    o = db().execute("""SELECT o.*, p.name pname, k.key_enc FROM orders o JOIN products p ON p.id=o.product_id
                        LEFT JOIN keys k ON k.id=o.key_id WHERE o.id=?""", (oid,)).fetchone()
    if not o or (o["user_id"] != g.user["id"] and g.user["role"] != "admin"): abort(404)
    key = fernet.decrypt(o["key_enc"]).decode() if o["key_enc"] else None
    r = make_response(render_template("order.html", o=o, key=key))
    r.headers["Cache-Control"] = "no-store"
    return r


# ---------- admin ----------
@app.route("/admin")
@admin_required
def admin_home():
    q = lambda s: db().execute(s).fetchone()[0]
    stats = {"Customers": q("SELECT COUNT(*) FROM users WHERE role='customer'"), "Products": q("SELECT COUNT(*) FROM products"),
             "Orders": q("SELECT COUNT(*) FROM orders"), "Pending top-ups": q("SELECT COUNT(*) FROM topups WHERE status='pending'"),
             "Unused keys": q("SELECT COUNT(*) FROM keys WHERE status='unused'")}
    return render_template("admin_home.html", stats=stats, customers=stats["Customers"], products=stats["Products"], orders=stats["Orders"], pending_topups=stats["Pending top-ups"], unused_keys=stats["Unused keys"])


@app.route("/admin/products", methods=["GET", "POST"])
@admin_required
def admin_products():
    d = db()
    if request.method == "POST":
        pid = request.form.get("id")
        try: price = int(request.form["price"]); assert price > 0
        except Exception: flash("Enter a valid price."); return redirect(url_for("admin_products"))
        img = save_image(request.files.get("image"))
        vals = (request.form["name"].strip()[:120], request.form.get("description", "")[:2000], price,
                1 if request.form.get("active") else 0, now())
        if pid:
            d.execute("UPDATE products SET name=?,description=?,price=?,active=?,updated_at=? WHERE id=?", (*vals, int(pid)))
            if img: d.execute("UPDATE products SET image=? WHERE id=?", (img, int(pid)))
            audit("product.update", f"product:{pid}", str(vals[:3]))
        else:
            c = d.execute("INSERT INTO products(name,description,price,active,created_at,updated_at,image) VALUES(?,?,?,?,?,?,?)",
                          (*vals, vals[4], img))
            audit("product.create", f"product:{c.lastrowid}", vals[0])
        return redirect(url_for("admin_products"))
    rows = d.execute("""SELECT p.*, (SELECT COUNT(*) FROM keys k WHERE k.product_id=p.id AND k.status='unused') unused,
                        (SELECT COUNT(*) FROM keys k WHERE k.product_id=p.id AND k.status='sold') sold FROM products p""").fetchall()
    return render_template("admin_products.html", products=rows)


@app.route("/admin/keys", methods=["GET", "POST"])
@admin_required
def admin_keys():
    d = db()
    if request.method == "POST":
        pid = int(request.form["product_id"]); added = dup = 0
        for line in request.form["keys"].splitlines():
            k = line.strip()
            if not k: continue
            h = __import__("hashlib").sha256(k.encode()).hexdigest()
            try:
                d.execute("INSERT INTO keys(product_id,key_enc,key_hash,created_at) VALUES(?,?,?,?)",
                          (pid, fernet.encrypt(k.encode()), h, now())); added += 1
            except sqlite3.IntegrityError: dup += 1
        audit("keys.add", f"product:{pid}", f"added={added} duplicates={dup}")
        flash(f"{added} key(s) added, {dup} duplicate(s) skipped.")
        return redirect(url_for("admin_keys"))
    return render_template("admin_keys.html", products=d.execute("SELECT id,name FROM products").fetchall(),
        keys=d.execute("""SELECT k.id,k.status,k.order_id,p.name FROM keys k JOIN products p ON p.id=k.product_id
                          ORDER BY k.id DESC LIMIT 200""").fetchall())


@app.route("/admin/keys/<int:kid>/delete", methods=["POST"])
@admin_required
def admin_key_delete(kid):
    if db().execute("DELETE FROM keys WHERE id=? AND status='unused'", (kid,)).rowcount:
        audit("keys.delete", f"key:{kid}")
    else: flash("Sold keys cannot be deleted.")
    return redirect(url_for("admin_keys"))


@app.route("/admin/customers")
@admin_required
def admin_customers():
    return render_template("admin_customers.html",
                           rows=db().execute("SELECT * FROM users WHERE role='customer' ORDER BY id DESC").fetchall())


@app.route("/admin/customers/<int:uid>")
@admin_required
def admin_customer(uid):
    d = db()
    u = d.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() or abort(404)
    return render_template("admin_customer.html", c=u,
        orders=d.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall(),
        led=d.execute("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall())


@app.route("/admin/customers/<int:uid>/toggle", methods=["POST"])
@admin_required
def admin_customer_toggle(uid):
    db().execute("UPDATE users SET active=1-active WHERE id=? AND role='customer'", (uid,))
    audit("customer.toggle", f"user:{uid}"); return redirect(url_for("admin_customer", uid=uid))


@app.route("/admin/orders")
@admin_required
def admin_orders():
    return render_template("admin_orders.html", rows=db().execute("""SELECT o.*, u.email, p.name pname FROM orders o
        JOIN users u ON u.id=o.user_id JOIN products p ON p.id=o.product_id ORDER BY o.id DESC LIMIT 300""").fetchall())


@app.route("/admin/topups")
@admin_required
def admin_topups():
    return render_template("admin_topups.html", rows=db().execute("""SELECT t.*, u.email FROM topups t JOIN users u ON u.id=t.user_id
        ORDER BY (t.status='pending') DESC, t.id DESC LIMIT 300""").fetchall())


@app.route("/admin/topups/<int:tid>/<action>", methods=["POST"])
@admin_required
def admin_topup_review(tid, action):
    if action not in ("approve", "reject"): abort(404)
    d = db()
    try:
        d.execute("BEGIN IMMEDIATE")
        t = d.execute("SELECT * FROM topups WHERE id=?", (tid,)).fetchone() or abort(404)
        status = "approved" if action == "approve" else "rejected"
        # status guard makes the review exactly-once even on retries / double clicks
        cur = d.execute("UPDATE topups SET status=?, reviewed_by=?, reviewed_at=?, reason=? WHERE id=? AND status='pending'",
                        (status, g.user["id"], now(), request.form.get("reason", "")[:200], tid))
        if cur.rowcount != 1:
            d.execute("ROLLBACK"); flash("This request was already reviewed."); return redirect(url_for("admin_topups"))
        if action == "approve":
            d.execute("UPDATE users SET balance=balance+? WHERE id=?", (t["amount"], t["user_id"]))
            d.execute("INSERT INTO ledger(user_id,type,amount,ref,created_at) VALUES(?,?,?,?,?)",
                      (t["user_id"], "topup", t["amount"], f"UTR:{t['utr']}", now()))
        audit(f"topup.{status}", f"topup:{tid}", f"user={t['user_id']} amount={t['amount']} utr={t['utr']}")
        d.execute("COMMIT")
    except Exception:
        if d.in_transaction: d.execute("ROLLBACK")
        raise
    return redirect(url_for("admin_topups"))


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        yt = request.form.get("youtube_url", "").strip()
        if yt and not yt.startswith("https://"): flash("YouTube URL must start with https://"); return redirect(url_for("admin_settings"))
        for k in ("store_name", "upi_id", "support_links"):
            set_setting(k, request.form.get(k, "").strip()[:2000])
        set_setting("youtube_url", yt)
        for field, key in (("banner", "banner"), ("upi_qr", "upi_qr")):
            n = save_image(request.files.get(field))
            if n: set_setting(key, n)
        audit("settings.update", "settings"); flash("Settings saved.")
        return redirect(url_for("admin_settings"))
    return render_template("admin_settings.html", s={k: setting(k) for k in
                           ("store_name", "upi_id", "youtube_url", "support_links")})


@app.route("/admin/audit")
@admin_required
def admin_audit():
    return render_template("admin_audit.html", rows=db().execute("SELECT * FROM audit ORDER BY id DESC LIMIT 300").fetchall())


# ---------- templates ----------
BASE_T = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ store_name }}</title><style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
:root{
  --bg:#0a0e17;
  --bg-gradient:linear-gradient(135deg,#0a0e17 0%,#1a1f2e 50%,#0d1117 100%);
  --panel:rgba(26,31,46,0.8);
  --panel-glass:rgba(26,31,46,0.6);
  --line:rgba(107,114,128,0.2);
  --tx:#e8ecf4;
  --mut:#9ca3af;
  --acc:#00d4ff;
  --acc-gradient:linear-gradient(135deg,#00d4ff 0%,#0099ff 100%);
  --acc-glow:rgba(0,212,255,0.3);
  --bad:#ff4757;
  --bad-gradient:linear-gradient(135deg,#ff4757 0%,#ff2e43 100%);
  --success:#2ed573;
  --warning:#ffa502;
  --purple:#a855f7;
  --purple-gradient:linear-gradient(135deg,#a855f7 0%,#7c3aed 100%);
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:'Inter',system-ui,-apple-system,sans-serif;
  background:var(--bg-gradient);
  background-attachment:fixed;
  color:var(--tx);
  min-height:100vh;
  line-height:1.6;
  overflow-x:hidden
}
body::before{
  content:'';
  position:fixed;
  top:0;left:0;right:0;bottom:0;
  background:radial-gradient(circle at 20% 50%,rgba(0,212,255,0.15) 0%,transparent 50%),
              radial-gradient(circle at 80% 20%,rgba(168,85,247,0.15) 0%,transparent 50%),
              radial-gradient(circle at 40% 80%,rgba(46,213,115,0.1) 0%,transparent 50%),
              radial-gradient(circle at 60% 40%,rgba(255,71,87,0.08) 0%,transparent 40%),
              radial-gradient(circle at 10% 90%,rgba(255,165,2,0.1) 0%,transparent 45%);
  pointer-events:none;
  z-index:0;
  animation:bgPulse 8s ease-in-out infinite
}
@keyframes bgPulse{
  0%,100%{opacity:1}
  50%{opacity:0.7}
}
body::after{
  content:'';
  position:fixed;
  top:0;left:0;right:0;bottom:0;
  background-image:
    linear-gradient(rgba(0,212,255,0.03) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,212,255,0.03) 1px,transparent 1px);
  background-size:50px 50px;
  pointer-events:none;
  z-index:0;
  animation:gridMove 20s linear infinite
}
@keyframes gridMove{
  0%{transform:translate(0,0)}
  100%{transform:translate(50px,50px)}
}
a{color:var(--acc);text-decoration:none;transition:all 0.3s ease}
a:hover{color:#00b8e6;text-shadow:0 0 20px var(--acc-glow)}
header{
  position:sticky;
  top:0;
  z-index:100;
  padding:16px 5vw;
  display:flex;
  gap:20px;
  align-items:center;
  flex-wrap:wrap;
  background:linear-gradient(180deg,rgba(10,14,23,0.98) 0%,rgba(10,14,23,0.9) 100%);
  backdrop-filter:blur(20px);
  border-bottom:1px solid var(--line);
  box-shadow:0 4px 30px rgba(0,0,0,0.4),0 0 60px rgba(0,212,255,0.1);
  animation:headerGlow 3s ease-in-out infinite
}
@keyframes headerGlow{
  0%,100%{box-shadow:0 4px 30px rgba(0,0,0,0.4),0 0 60px rgba(0,212,255,0.1)}
  50%{box-shadow:0 4px 30px rgba(0,0,0,0.4),0 0 80px rgba(0,212,255,0.2)}
}
header b{
  font-size:1.5rem;
  font-weight:800;
  margin-right:auto;
  background:var(--acc-gradient);
  -webkit-background-clip:text;
  -webkit-text-fill-color:transparent;
  background-clip:text;
  letter-spacing:-0.5px
}
header a{
  padding:8px 16px;
  border-radius:8px;
  font-weight:500;
  transition:all 0.3s ease
}
header a:hover{
  background:rgba(0,212,255,0.1);
  transform:translateY(-2px)
}
footer{
  border-top:1px solid var(--line);
  margin-top:60px;
  padding:30px 5vw;
  color:var(--mut);
  text-align:center;
  background:rgba(10,14,23,0.8);
  backdrop-filter:blur(10px)
}
footer a{
  margin:0 15px;
  color:var(--mut);
  transition:all 0.3s ease
}
footer a:hover{
  color:var(--acc)
}
main{
  position:relative;
  z-index:1;
  padding:40px 5vw;
  max-width:1200px;
  margin:auto
}
h1,h2,h3{
  line-height:1.2;
  font-weight:700;
  margin-bottom:20px
}
h1{
  font-size:2.5rem;
  background:var(--acc-gradient);
  -webkit-background-clip:text;
  -webkit-text-fill-color:transparent;
  background-clip:text;
  margin-bottom:30px
}
h2{
  font-size:1.8rem;
  color:var(--tx)
}
h3{
  font-size:1.3rem;
  color:var(--tx)
}
.grid{
  display:grid;
  grid-template-columns:repeat(auto-fill,minmax(280px,1fr));
  gap:24px
}
.card{
  background:var(--panel);
  backdrop-filter:blur(10px);
  border:1px solid var(--line);
  border-radius:16px;
  padding:20px;
  transition:all 0.4s cubic-bezier(0.4,0,0.2,1);
  position:relative;
  overflow:hidden;
  animation:cardEntrance 0.6s ease-out
}
@keyframes cardEntrance{
  from{opacity:0;transform:translateY(30px)}
  to{opacity:1;transform:translateY(0)}
}
.card::before{
  content:'';
  position:absolute;
  top:0;left:0;right:0;bottom:0;
  background:linear-gradient(135deg,rgba(0,212,255,0.15) 0%,rgba(168,85,247,0.1) 50%,transparent 100%);
  opacity:0;
  transition:opacity 0.4s ease;
  pointer-events:none
}
.card::after{
  content:'';
  position:absolute;
  top:-50%;left:-50%;width:200%;height:200%;
  background:conic-gradient(from 0deg,transparent,rgba(0,212,255,0.1),transparent 30%);
  animation:rotate 4s linear infinite;
  opacity:0;
  transition:opacity 0.4s ease;
  pointer-events:none
}
@keyframes rotate{
  100%{transform:rotate(360deg)}
}
.card:hover{
  transform:translateY(-12px) scale(1.02);
  box-shadow:0 25px 50px rgba(0,212,255,0.2),
              0 0 60px rgba(0,212,255,0.15),
              inset 0 0 30px rgba(0,212,255,0.05);
  border-color:rgba(0,212,255,0.5)
}
.card:hover::before{
  opacity:1
}
.card:hover::after{
  opacity:1
}
.card img,.banner{
  width:100%;
  border-radius:12px;
  display:block;
  object-fit:cover;
  transition:transform 0.4s ease
}
.card img{
  aspect-ratio:4/3;
  margin-bottom:16px
}
.card:hover img{
  transform:scale(1.05)
}
.banner{
  max-height:300px;
  margin-bottom:30px;
  box-shadow:0 10px 30px rgba(0,0,0,0.3)
}
input,textarea,select{
  font:inherit;
  padding:14px 16px;
  border-radius:12px;
  border:2px solid var(--line);
  background:rgba(14,18,26,0.8);
  color:var(--tx);
  max-width:100%;
  width:100%;
  transition:all 0.3s ease;
  backdrop-filter:blur(10px)
}
input:focus,textarea:focus,select:focus{
  outline:none;
  border-color:var(--acc);
  box-shadow:0 0 20px var(--acc-glow);
  transform:translateY(-2px)
}
input::placeholder,textarea::placeholder{
  color:var(--mut)
}
button,.btn{
  background:var(--acc-gradient);
  color:#0a0e17;
  border:0;
  font-weight:700;
  cursor:pointer;
  text-decoration:none;
  padding:14px 28px;
  border-radius:12px;
  display:inline-block;
  transition:all 0.3s ease;
  box-shadow:0 4px 15px var(--acc-glow),0 0 30px rgba(0,212,255,0.2);
  position:relative;
  overflow:hidden;
  animation:buttonPulse 2s ease-in-out infinite
}
@keyframes buttonPulse{
  0%,100%{box-shadow:0 4px 15px var(--acc-glow),0 0 30px rgba(0,212,255,0.2)}
  50%{box-shadow:0 4px 15px var(--acc-glow),0 0 50px rgba(0,212,255,0.4)}
}
button::before,.btn::before{
  content:'';
  position:absolute;
  top:50%;left:50%;
  width:0;height:0;
  background:rgba(255,255,255,0.3);
  border-radius:50%;
  transform:translate(-50%,-50%);
  transition:width 0.6s,height 0.6s
}
button:hover::before,.btn:hover::before{
  width:300px;height:300px
}
button:hover,.btn:hover{
  transform:translateY(-4px) scale(1.05);
  box-shadow:0 8px 30px var(--acc-glow),0 0 60px rgba(0,212,255,0.4);
  animation:buttonGlow 0.5s ease-in-out
}
@keyframes buttonGlow{
  0%,100%{filter:brightness(1)}
  50%{filter:brightness(1.2)}
}
button:active,.btn:active{
  transform:translateY(-2px) scale(0.98)
}
button.alt{
  background:transparent;
  color:var(--tx);
  border:2px solid var(--line);
  box-shadow:none
}
button.alt:hover{
  border-color:var(--acc);
  background:rgba(0,212,255,0.1)
}
button.bad{
  background:var(--bad-gradient);
  color:#fff;
  box-shadow:0 4px 15px rgba(255,71,87,0.3)
}
button.bad:hover{
  box-shadow:0 8px 25px rgba(255,71,87,0.4)
}
form.stack>*{
  display:block;
  margin:12px 0;
  width:100%;
  max-width:450px
}
form.stack label{
  display:block;
  margin-bottom:8px;
  font-weight:500;
  color:var(--tx)
}
form.inline{
  display:inline
}
table{
  width:100%;
  border-collapse:collapse;
  display:block;
  overflow-x:auto;
  background:var(--panel);
  border-radius:12px;
  overflow:hidden
}
td,th{
  padding:16px;
  border-bottom:1px solid var(--line);
  text-align:left
}
th{
  background:rgba(0,212,255,0.1);
  font-weight:600;
  color:var(--acc);
  text-transform:uppercase;
  font-size:0.85rem;
  letter-spacing:0.5px
}
tr:hover td{
  background:rgba(0,212,255,0.05)
}
.flash{
  background:rgba(0,212,255,0.15);
  border-left:4px solid var(--acc);
  padding:16px 20px;
  margin:16px 0;
  border-radius:8px;
  backdrop-filter:blur(10px);
  animation:slideIn 0.5s ease
}
@keyframes slideIn{
  from{opacity:0;transform:translateX(-20px)}
  to{opacity:1;transform:translateX(0)}
}
.muted{color:var(--mut)}
code.key{
  background:rgba(14,18,26,0.9);
  padding:16px 20px;
  border-radius:12px;
  display:block;
  user-select:all;
  word-break:break-all;
  font-family:'Courier New',monospace;
  font-size:0.95rem;
  border:2px solid var(--line);
  color:var(--acc);
  text-shadow:0 0 10px var(--acc-glow)
}
a:focus-visible,button:focus-visible,input:focus-visible{
  outline:3px solid var(--acc);
  outline-offset:3px
}
.stat-card{
  text-align:center;
  padding:30px
}
.stat-card .muted{
  font-size:0.9rem;
  text-transform:uppercase;
  letter-spacing:1px;
  margin-bottom:10px
}
.stat-card h2{
  font-size:3rem;
  background:var(--purple-gradient);
  -webkit-background-clip:text;
  -webkit-text-fill-color:transparent;
  background-clip:text;
  margin:0
}
.status-badge{
  display:inline-block;
  padding:6px 12px;
  border-radius:20px;
  font-size:0.85rem;
  font-weight:600;
  text-transform:uppercase
}
.status-completed{background:rgba(46,213,115,0.2);color:var(--success)}
.status-pending{background:rgba(255,165,2,0.2);color:var(--warning)}
.status-rejected{background:rgba(255,71,87,0.2);color:var(--bad)}
.price-tag{
  font-size:1.5rem;
  font-weight:700;
  color:var(--acc);
  text-shadow:0 0 15px var(--acc-glow)
}
.stock-indicator{
  display:inline-flex;
  align-items:center;
  gap:6px;
  padding:6px 12px;
  border-radius:20px;
  font-size:0.85rem;
  font-weight:500
}
.stock-in{background:rgba(46,213,115,0.2);color:var(--success)}
.stock-out{background:rgba(255,71,87,0.2);color:var(--bad)}
.stock-indicator::before{
  content:'';
  width:8px;height:8px;
  border-radius:50%;
  background:currentColor;
  animation:dotPulse 1.5s ease-in-out infinite
}
@keyframes dotPulse{
  0%,100%{transform:scale(1);opacity:1}
  50%{transform:scale(1.3);opacity:0.7}
}
.floating-particles{
  position:fixed;
  top:0;left:0;right:0;bottom:0;
  pointer-events:none;
  z-index:0;
  overflow:hidden
}
.particle{
  position:absolute;
  width:4px;height:4px;
  background:var(--acc);
  border-radius:50%;
  opacity:0.3;
  animation:float 15s linear infinite
}
@keyframes float{
  0%{transform:translateY(100vh) rotate(0deg);opacity:0}
  10%{opacity:0.3}
  90%{opacity:0.3}
  100%{transform:translateY(-100vh) rotate(720deg);opacity:0}
}
.shimmer{
  position:relative;
  overflow:hidden
}
.shimmer::after{
  content:'';
  position:absolute;
  top:0;left:-100%;
  width:100%;height:100%;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,0.2),transparent);
  animation:shimmer 3s infinite
}
@keyframes shimmer{
  0%{left:-100%}
  100%{left:100%}
}
.glow-text{
  text-shadow:0 0 10px var(--acc-glow),0 0 20px var(--acc-glow),0 0 30px var(--acc-glow)
}
.neon-border{
  box-shadow:0 0 5px var(--acc),0 0 10px var(--acc),0 0 20px var(--acc),0 0 40px var(--acc)
}
@media(max-width:768px){
  header{padding:12px 20px}
  header b{font-size:1.2rem}
  main{padding:20px}
  h1{font-size:1.8rem}
  .grid{grid-template-columns:1fr}
  form.stack>*{max-width:100%}
}</style></head><body>
<header><b><a href="/" style="text-decoration:none;color:inherit">{{ store_name }}</a></b>
{% if user %}{% if user.role=='admin' %}<a href="{{ url_for('admin_home') }}">Admin</a>{% else %}
<a href="{{ url_for('orders') }}">My orders</a><a href="{{ url_for('wallet') }}">Wallet ₹{{ user.balance }}</a>{% endif %}
<form class="inline" method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="alt">Sign out</button></form>
{% else %}<a href="{{ url_for('login') }}">Sign in</a><a href="{{ url_for('register') }}">Create account</a>{% endif %}</header>
<div class="floating-particles">
  <div class="particle" style="left:10%;animation-delay:0s"></div>
  <div class="particle" style="left:20%;animation-delay:2s"></div>
  <div class="particle" style="left:30%;animation-delay:4s"></div>
  <div class="particle" style="left:40%;animation-delay:1s"></div>
  <div class="particle" style="left:50%;animation-delay:3s"></div>
  <div class="particle" style="left:60%;animation-delay:5s"></div>
  <div class="particle" style="left:70%;animation-delay:2.5s"></div>
  <div class="particle" style="left:80%;animation-delay:4.5s"></div>
  <div class="particle" style="left:90%;animation-delay:1.5s"></div>
  <div class="particle" style="left:15%;animation-delay:3.5s"></div>
  <div class="particle" style="left:25%;animation-delay:5.5s"></div>
  <div class="particle" style="left:35%;animation-delay:0.5s"></div>
  <div class="particle" style="left:45%;animation-delay:2.2s"></div>
  <div class="particle" style="left:55%;animation-delay:4.2s"></div>
  <div class="particle" style="left:65%;animation-delay:1.2s"></div>
  <div class="particle" style="left:75%;animation-delay:3.2s"></div>
  <div class="particle" style="left:85%;animation-delay:5.2s"></div>
  <div class="particle" style="left:95%;animation-delay:2.7s"></div>
</div>
<main>{% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}{% block body %}{% endblock %}</main>
<footer>{% for l,u in support_links %}<a href="{{ u }}" rel="noopener noreferrer" target="_blank">{{ l }}</a>{% endfor %}</footer></body></html>"""

CSRF = '<input type="hidden" name="csrf" value="{{ csrf }}">'
ADMIN_NAV = ("<div style='display:flex;gap:12px;flex-wrap:wrap;margin-bottom:30px'>" + "".join(f'<a href="{{{{ url_for(\'{e}\') }}}}" style="padding:10px 20px;background:rgba(0,212,255,0.1);border-radius:10px;border:1px solid rgba(0,212,255,0.3);transition:all 0.3s ease">{n}</a> ' for e, n in [
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
<div class="card shimmer" style="text-align:center;padding:60px 40px;margin-bottom:40px;background:linear-gradient(135deg,rgba(0,212,255,0.1) 0%,rgba(168,85,247,0.1) 100%);border:2px solid rgba(0,212,255,0.3)">
<h1 class="glow-text" style="font-size:3.5rem;margin-bottom:20px">🎮 Game Keys Store</h1>
<p style="font-size:1.3rem;color:var(--mut);margin-bottom:30px">Your premium destination for authentic game keys at unbeatable prices</p>
<div style="display:flex;gap:20px;justify-content:center;flex-wrap:wrap">
<div style="text-align:center;padding:20px"><div style="font-size:2.5rem;margin-bottom:10px">🔒</div><div style="font-weight:600">Secure</div></div>
<div style="text-align:center;padding:20px"><div style="font-size:2.5rem;margin-bottom:10px">⚡</div><div style="font-weight:600">Instant</div></div>
<div style="text-align:center;padding:20px"><div style="font-size:2.5rem;margin-bottom:10px">💎</div><div style="font-weight:600">Premium</div></div>
</div>
</div>
{% if not products %}<p class="muted">No products yet. Check back soon.</p>{% endif %}<div class="grid">
{% for p in products %}<a class="card shimmer" href="{{ url_for('product', pid=p.id) }}" style="text-decoration:none;color:inherit">
{% if p.image %}<img src="{{ url_for('uploads', name=p.image) }}" alt="">{% endif %}<h3>🎮 {{ p.name }}</h3>
<p class="price-tag">💰 ₹{{ p.price }}</p>
<span class="stock-indicator {{ 'stock-in' if p.stock else 'stock-out' }}">{{ '✅ In stock' if p.stock else '❌ Out of stock' }}</span></a>{% endfor %}</div>"""),
 "product.html": page("""<div class="card shimmer" style="max-width:700px;margin:0 auto">{% if p.image %}<img src="{{ url_for('uploads', name=p.image) }}" alt="" style="max-width:100%;margin-bottom:30px;border-radius:16px;box-shadow:0 10px 40px rgba(0,212,255,0.2)">{% endif %}
<h1 class="glow-text" style="font-size:2.5rem">{{ p.name }}</h1><p style="color:var(--mut);font-size:1.2rem;line-height:1.8;margin:20px 0">{{ p.description }}</p>
<div style="margin:30px 0;padding:30px;background:linear-gradient(135deg,rgba(0,212,255,0.1) 0%,rgba(168,85,247,0.1) 100%);border-radius:16px;border:2px solid rgba(0,212,255,0.3)">
<div style="font-size:1.2rem;color:var(--mut);margin-bottom:10px">Price</div>
<div class="price-tag glow-text" style="font-size:3.5rem">₹{{ p.price }}</div>
</div>
{% if p.stock %}{% if user %}<form method="post" action="{{ url_for('buy', pid=p.id) }}">""" + CSRF + """<button style="font-size:1.2rem;padding:18px 40px">🎮 Buy with wallet</button></form>
{% else %}<a class="btn" href="{{ url_for('login') }}" style="font-size:1.2rem;padding:18px 40px">Sign in to buy</a>{% endif %}{% else %}<p class="muted" style="background:rgba(255,71,87,0.2);padding:20px;border-radius:12px;color:var(--bad);font-size:1.2rem;text-align:center">❌ Out of stock</p>{% endif %}</div>"""),
 "register.html": page("""<div class="card shimmer" style="max-width:500px;margin:0 auto;text-align:center;padding:40px"><h1 class="glow-text" style="font-size:2.5rem">✨ Create Account</h1>
<p style="color:var(--mut);margin-bottom:30px">Join us and start gaming today!</p>
<form class="stack" method="post" style="max-width:100%">""" + CSRF + """<label>Name<input name="name" placeholder="Enter your name" required></label>
<label>Email<input name="email" type="email" placeholder="your@email.com" required></label><label>Password<input name="password" type="password" minlength="8" placeholder="Min 8 characters" required></label><button style="font-size:1.1rem;padding:16px 32px">🚀 Create account</button></form></div>"""),
 "login.html": page("""<div class="card shimmer" style="max-width:500px;margin:0 auto;text-align:center;padding:40px"><h1 class="glow-text" style="font-size:2.5rem">🔐 Sign In</h1>
<p style="color:var(--mut);margin-bottom:30px">Welcome back! Let's get you gaming.</p>
<form class="stack" method="post" style="max-width:100%">""" + CSRF + """<label>Email<input name="email" type="email" placeholder="your@email.com" required></label>
<label>Password<input name="password" type="password" placeholder="Your password" required></label><button style="font-size:1.1rem;padding:16px 32px">🎮 Sign in</button></form></div>"""),
 "wallet.html": page("""<div class="card shimmer" style="max-width:700px;margin:0 auto;text-align:center;padding:50px;background:linear-gradient(135deg,rgba(0,212,255,0.15) 0%,rgba(168,85,247,0.15) 100%);border:2px solid rgba(0,212,255,0.4)"><h1 class="glow-text" style="font-size:2.5rem">💰 Wallet Balance</h1><div class="price-tag glow-text" style="font-size:5rem;margin:30px 0">₹{{ user.balance }}</div></div>
<div class="card shimmer" style="max-width:700px;margin:40px auto"><h2 style="font-size:1.8rem">➕ Add Funds</h2>
<p style="color:var(--mut);margin-bottom:25px;font-size:1.1rem">Pay with UPI, then submit the amount and UTR. Funds are added after an admin verifies the payment.</p>
{% if qr %}<img src="{{ url_for('uploads', name=qr) }}" alt="UPI QR code" style="max-width:280px;border-radius:16px;margin:25px auto;display:block;box-shadow:0 10px 40px rgba(0,212,255,0.2)">{% endif %}
{% if upi_id %}<p style="background:rgba(0,212,255,0.15);padding:16px 24px;border-radius:12px;display:inline-block;font-size:1.1rem;border:2px solid rgba(0,212,255,0.3)">💳 UPI ID: <b>{{ upi_id }}</b></p>{% endif %}
<form class="stack" method="post">""" + CSRF + """<label>💰 Amount paid (₹)<input name="amount" type="number" min="{{ min }}" placeholder="Min ₹{{ min }}" required></label>
<label>🔢 UTR / Reference<input name="utr" placeholder="12-digit UTR number" required></label><button style="font-size:1.1rem;padding:16px 32px">✅ Submit for verification</button></form></div>
<h2 class="glow-text" style="font-size:2rem">📋 Top-up Requests</h2>""" + table(["📅 Date", "💰 Amount", "🔢 UTR", "📊 Status", "📝 Note"], "<td>{{ r.created_at }}</td><td>₹{{ r.amount }}</td><td>{{ r.utr }}</td><td><span class=\"status-badge status-{{ r.status }}\">{{ r.status|capitalize }}</span></td><td>{{ r.reason or '' }}</td>").replace("rows", "tops") + """
<h2 class="glow-text" style="font-size:2rem">📊 Transaction History</h2>""" + table(["📅 Date", "📝 Type", "💰 Amount", "🔗 Reference"], "<td>{{ r.created_at }}</td><td>{{ r.type }}</td><td>{{ r.amount }}</td><td>{{ r.ref }}</td>").replace("rows", "led")),
 "orders.html": page("<h1 class=\"glow-text\" style=\"font-size:2.5rem\">📦 My Orders</h1>" + table(["📋 Order", "🎮 Product", "💰 Amount", "📅 Date", "📊 Status", "⚡ Action"],
   "<td>{{ r.ref }}</td><td>{{ r.pname }}</td><td>₹{{ r.price }}</td><td>{{ r.created_at }}</td><td><span class=\"status-badge status-{{ r.status }}\">{{ r.status }}</span></td><td><a href=\"{{ url_for('order_detail', oid=r.id) }}\" class=\"btn\" style=\"padding:8px 16px;font-size:0.9rem\">👁️ View key</a></td>").replace("rows", "orders")),
 "order.html": page("""<div class="card shimmer" style="max-width:700px;margin:0 auto"><h1 class="glow-text" style="font-size:2.5rem">🎮 Order {{ o.ref }}</h1>
<p style="color:var(--mut);margin:25px 0;font-size:1.1rem">🎮 {{ o.pname }} · <span class="price-tag">₹{{ o.price }}</span> · 📅 {{ o.created_at }} · <span class="status-badge status-{{ o.status }}">{{ o.status }}</span></p>
{% if key %}<p style="margin-top:25px;font-weight:600;font-size:1.2rem">🔑 Your game key:</p><code class="key">{{ key }}</code>
<p style="margin-top:20px;color:var(--mut);font-size:1rem">🔒 Click to copy - Keep this key safe!</p>{% endif %}</div>"""),
 "admin_home.html": page('<div class="card shimmer" style="text-align:center;padding:50px;margin-bottom:40px;background:linear-gradient(135deg,rgba(168,85,247,0.15) 0%,rgba(0,212,255,0.15) 100%);border:2px solid rgba(168,85,247,0.4)"><h1 class="glow-text" style="font-size:3rem">📊 Admin Dashboard</h1><p style="color:var(--mut);font-size:1.2rem;margin-top:15px">Welcome back, Admin!</p></div><div class="grid"><div class="card stat-card shimmer" style="background:linear-gradient(135deg,rgba(0,212,255,0.1) 0%,rgba(0,212,255,0.05) 100%)"><div style="font-size:3rem;margin-bottom:15px">👥</div><div class="muted">Customers</div><h2 class="glow-text">{{ customers }}</h2></div><div class="card stat-card shimmer" style="background:linear-gradient(135deg,rgba(168,85,247,0.1) 0%,rgba(168,85,247,0.05) 100%)"><div style="font-size:3rem;margin-bottom:15px">🎮</div><div class="muted">Products</div><h2 class="glow-text">{{ products }}</h2></div><div class="card stat-card shimmer" style="background:linear-gradient(135deg,rgba(46,213,115,0.1) 0%,rgba(46,213,115,0.05) 100%)"><div style="font-size:3rem;margin-bottom:15px">📦</div><div class="muted">Orders</div><h2 class="glow-text">{{ orders }}</h2></div><div class="card stat-card shimmer" style="background:linear-gradient(135deg,rgba(255,165,2,0.1) 0%,rgba(255,165,2,0.05) 100%)"><div style="font-size:3rem;margin-bottom:15px">💰</div><div class="muted">Pending Top-ups</div><h2 class="glow-text">{{ pending_topups }}</h2></div><div class="card stat-card shimmer" style="background:linear-gradient(135deg,rgba(255,71,87,0.1) 0%,rgba(255,71,87,0.05) 100%)"><div style="font-size:3rem;margin-bottom:15px">🔑</div><div class="muted">Unused Keys</div><h2 class="glow-text">{{ unused_keys }}</h2></div></div>', True),
 "admin_products.html": page("""<h1 class="glow-text" style="font-size:2.5rem">🎮 Products Management</h1><div class="card shimmer"><h3 style="font-size:1.5rem;margin-bottom:20px">➕ Add New Product</h3><form class="stack" method="post" enctype="multipart/form-data">""" + CSRF + """
<label>📝 Product Name<input name="name" placeholder="e.g., GTA V Premium Edition" required></label><label>📄 Description<textarea name="description" placeholder="Product description..." rows="3"></textarea></label><label>💰 Price (₹)<input name="price" type="number" min="1" placeholder="999" required></label>
<label>🖼️ Product Image<input type="file" name="image" accept="image/png,image/jpeg,image/webp"></label><label style="display:flex;align-items:center;gap:8px"><input type="checkbox" name="active" checked style="width:auto"> ✅ Active (visible in store)</label><button>📦 Add Product</button></form></div>
{% for p in products %}<div class="card shimmer" style="margin-top:25px"><h3 style="font-size:1.5rem;margin-bottom:20px">✏️ Edit: {{ p.name }}</h3><form class="stack" method="post" enctype="multipart/form-data">""" + CSRF + """<input type="hidden" name="id" value="{{ p.id }}">
<label>📝 Product Name<input name="name" value="{{ p.name }}" required></label><label>📄 Description<textarea name="description" rows="3">{{ p.description }}</textarea></label><label>💰 Price (₹)<input name="price" type="number" min="1" value="{{ p.price }}"></label>
<label>🖼️ Product Image<input type="file" name="image" accept="image/png,image/jpeg,image/webp"></label><label style="display:flex;align-items:center;gap:8px"><input type="checkbox" name="active" {{ 'checked' if p.active }} style="width:auto"> ✅ Active</label>
<div style="margin-top:15px;padding:15px;background:rgba(0,212,255,0.15);border-radius:12px;border:2px solid rgba(0,212,255,0.3)"><span class="muted" style="font-size:1.1rem">📊 {{ p.unused }} unused keys · {{ p.sold }} sold</span></div><button>💾 Save Changes</button></form></div>{% endfor %}""", True),
 "admin_keys.html": page("""<h1 class="glow-text" style="font-size:2.5rem">🔑 Key Inventory</h1><div class="card shimmer" style="max-width:600px;margin-bottom:30px"><h3 style="font-size:1.5rem;margin-bottom:20px">➕ Add Keys</h3><form class="stack" method="post">""" + CSRF + """<label>🎮 Select Product<select name="product_id">{% for p in products %}<option value="{{ p.id }}">{{ p.name }}</option>{% endfor %}</select></label>
<label>🔑 Keys (one per line)<textarea name="keys" rows="8" placeholder="XXXX-XXXX-XXXX-XXXX&#10;YYYY-YYYY-YYYY-YYYY" required></textarea></label><button>📥 Add Keys</button></form></div>
<table><tr><th>🆔 ID</th><th>🎮 Product</th><th>📊 Status</th><th>📦 Order</th><th>⚡ Action</th></tr>{% for k in keys %}<tr><td>{{ k.id }}</td><td>{{ k.name }}</td><td><span class="status-badge status-{{ k.status }}">{{ k.status }}</span></td><td>{{ k.order_id or '-' }}</td>
<td>{% if k.status=='unused' %}<form class="inline" method="post" action="{{ url_for('admin_key_delete', kid=k.id) }}">""" + CSRF + """<button class="bad" style="padding:8px 16px;font-size:0.85rem">🗑️ Delete</button></form>{% else %}<span class="muted">-</span>{% endif %}</td></tr>{% endfor %}</table>""", True),
 "admin_customers.html": page("<h1 class=\"glow-text\" style=\"font-size:2.5rem\">👥 Customers</h1>" + table(["👤 Name", "📧 Email", "💰 Balance", "✅ Active", "⚡ Action"],
   "<td>{{ r.name }}</td><td>{{ r.email }}</td><td><span class=\"price-tag\">₹{{ r.balance }}</span></td><td><span class=\"status-badge {{ 'status-completed' if r.active else 'status-rejected' }}\">{{ 'Active' if r.active else 'Disabled' }}</span></td><td><a href=\"{{ url_for('admin_customer', uid=r.id) }}\" class=\"btn\" style=\"padding:8px 16px;font-size:0.9rem\">👁️ View</a></td>"), True),
 "admin_customer.html": page("""<div class="card shimmer" style="max-width:800px;margin:0 auto"><h1 class="glow-text" style="font-size:2.5rem">👤 {{ c.name }}</h1><p class="muted" style="font-size:1.2rem">{{ c.email }}</p>
<p style="margin:25px 0"><span class="price-tag glow-text" style="font-size:2.5rem">💰 Balance: ₹{{ c.balance }}</span></p>
<form method="post" action="{{ url_for('admin_customer_toggle', uid=c.id) }}">""" + CSRF + """<button class="{{ 'bad' if c.active else 'alt' }}">{{ '🚫 Disable' if c.active else '✅ Enable' }} account</button></form></div>
<h2 class="glow-text" style="font-size:2rem">📦 Orders</h2>""" + table(["📋 Ref", "💰 Amount", "📅 Date", "📊 Status"], "<td><a href=\"{{ url_for('order_detail', oid=r.id) }}\">{{ r.ref }}</a></td><td>₹{{ r.price }}</td><td>{{ r.created_at }}</td><td><span class=\"status-badge status-{{ r.status }}\">{{ r.status }}</span></td>").replace("rows", "orders") + """
<h2 class="glow-text" style="font-size:2rem">📊 Transaction Ledger</h2>""" + table(["📅 Date", "📝 Type", "💰 Amount", "🔗 Ref"], "<td>{{ r.created_at }}</td><td>{{ r.type }}</td><td>{{ r.amount }}</td><td>{{ r.ref }}</td>").replace("rows", "led"), True),
 "admin_orders.html": page("<h1 class=\"glow-text\" style=\"font-size:2.5rem\">📦 All Orders</h1>" + table(["📋 Ref", "👤 Customer", "🎮 Product", "💰 Amount", "📅 Date", "📊 Status"],
   "<td><a href=\"{{ url_for('order_detail', oid=r.id) }}\">{{ r.ref }}</a></td><td>{{ r.email }}</td><td>{{ r.pname }}</td><td>₹{{ r.price }}</td><td>{{ r.created_at }}</td><td><span class=\"status-badge status-{{ r.status }}\">{{ r.status }}</span></td>"), True),
 "admin_topups.html": page("<h1 class=\"glow-text\" style=\"font-size:2.5rem\">💰 Top-up Requests</h1><p class='muted' style='background:rgba(255,165,2,0.15);padding:20px;border-radius:12px;border-left:4px solid var(--warning);font-size:1.1rem'>⚠️ Approve only after confirming the payment and amount in your UPI app or bank statement.</p>" + table(
   ["👤 Customer", "💰 Amount", "🔢 UTR", "📅 Submitted", "📊 Status", "⚡ Action"],
   "<td>{{ r.email }}</td><td><span class=\"price-tag\">₹{{ r.amount }}</span></td><td>{{ r.utr }}</td><td>{{ r.created_at }}</td><td><span class=\"status-badge status-{{ r.status }}\">{{ r.status }}</span></td><td>{% if r.status=='pending' %}"
   "<form class=\"inline\" method=\"post\" action=\"{{ url_for('admin_topup_review', tid=r.id, action='approve') }}\">" + CSRF + "<button style='padding:8px 16px;font-size:0.85rem'>✅ Approve</button></form> "
   "<form class=\"inline\" method=\"post\" action=\"{{ url_for('admin_topup_review', tid=r.id, action='reject') }}\">" + CSRF + "<input name=\"reason\" placeholder=\"Reason\" style='padding:8px 12px;font-size:0.85rem;width:150px'><button class=\"bad\" style='padding:8px 16px;font-size:0.85rem'>❌ Reject</button></form>{% else %}{{ r.reason or '-' }}{% endif %}</td>"), True),
 "admin_settings.html": page("""<h1 class="glow-text" style="font-size:2.5rem">⚙️ Store Settings</h1><div class="card shimmer" style="max-width:600px;margin:0 auto"><form class="stack" method="post" enctype="multipart/form-data">""" + CSRF + """
<label>🏪 Store Name<input name="store_name" value="{{ s.store_name }}" placeholder="My Game Store"></label><label>🖼️ Banner Image<input type="file" name="banner" accept="image/png,image/jpeg,image/webp"></label>
<label>🔗 Banner Click URL (YouTube, https)<input name="youtube_url" value="{{ s.youtube_url }}" placeholder="https://youtube.com/..."></label><label>💳 UPI ID<input name="upi_id" value="{{ s.upi_id }}" placeholder="yourname@upi"></label>
<label>📱 UPI QR Code Image<input type="file" name="upi_qr" accept="image/png,image/jpeg,image/webp"></label>
<label>🔗 Support Links (one per line: Label|https://url)<textarea name="support_links" rows="4" placeholder="Discord|https://discord.gg/...&#10;Telegram|https://t.me/...">{{ s.support_links }}</textarea></label><button>💾 Save Settings</button></form></div>""", True),
 "admin_audit.html": page("<h1>📜 Audit Log</h1>" + table(["Time", "Admin", "Action", "Target", "Detail"],
   "<td>{{ r.created_at }}</td><td>{{ r.admin_id or 'System' }}</td><td><span style=\"color:var(--acc)\">{{ r.action }}</span></td><td>{{ r.target }}</td><td>{{ r.detail }}</td>"), True),
}
app.jinja_loader = DictLoader(T)

init_db()
if __name__ == "__main__":
    app.run(debug=False)
