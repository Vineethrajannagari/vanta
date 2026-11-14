import app
import re

client = app.app.test_client()

print("--- Testing Routes ---")
# 1. Home
r = client.get('/')
assert r.status_code == 200, f"Home failed: {r.status_code}"
print("GET / -> 200 OK")

# 2. Extract CSRF from /login
r_login = client.get('/login')
assert r_login.status_code == 200
m = re.search(r'name="csrf" value="([^"]+)"', r_login.text)
csrf = m.group(1) if m else None
print(f"CSRF extracted from /login: {csrf}")
assert csrf is not None, "CSRF should be present in login form"

# 3. Customer login
r = client.post('/login', data={'email': 'customer@vanta.com', 'password': 'customer123', 'csrf': csrf}, follow_redirects=True)
assert r.status_code == 200
assert "Wallet" in r.text or "Sign out" in r.text, "Customer login failed"
print("POST /login -> Logged in successfully!")

# 4. View Wallet
r = client.get('/wallet')
assert r.status_code == 200
print("GET /wallet -> 200 OK")

# 5. View Orders
r = client.get('/orders')
assert r.status_code == 200
print("GET /orders -> 200 OK")

# 6. Admin login
m = re.search(r'name="csrf" value="([^"]+)"', r.text)
csrf = m.group(1) if m else csrf
r = client.post('/logout', data={'csrf': csrf}, follow_redirects=True)

r_login = client.get('/login')
m = re.search(r'name="csrf" value="([^"]+)"', r_login.text)
csrf = m.group(1)

r = client.post('/login', data={'email': 'admin@example.com', 'password': 'admin123', 'csrf': csrf}, follow_redirects=True)
assert "Admin Portal" in r.text or "Overview" in r.text, "Admin login failed"
print("Admin login -> Success!")

# 7. Admin routes
for route in ['/admin', '/admin/products', '/admin/keys', '/admin/customers', '/admin/orders', '/admin/topups', '/admin/settings', '/admin/audit']:
    r = client.get(route)
    assert r.status_code == 200, f"Admin route {route} failed: {r.status_code}"
    print(f"GET {route} -> 200 OK")

print("\nALL BACKEND ROUTES TESTED AND WORKING!")
