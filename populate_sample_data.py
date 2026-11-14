"""
Populate the database with sample data for testing
"""
import sqlite3
import os
from werkzeug.security import generate_password_hash
from cryptography.fernet import Fernet
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "store.db")

# Encryption key (use the same one from your app)
KEY_ENC_SECRET = "XAzYAa_WMvv2eSadxRPyc9fShB5nKJV_0DF0AsBfzVg="
fernet = Fernet(KEY_ENC_SECRET.encode())

def populate_data():
    """Populate database with sample data"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        print("Populating sample data...")

        # Sample products
        products = [
            ("Grand Theft Auto V Premium Edition", "Open world action-adventure game", 1499),
            ("Red Dead Redemption 2", "Epic western adventure", 2499),
            ("Cyberpunk 2077", "Futuristic open-world RPG", 1999),
            ("Elden Ring", "Action RPG by FromSoftware", 2999),
            ("God of War Ragnarok", "Epic Norse mythology adventure", 3499),
            ("Minecraft Java Edition", "Sandbox building game", 999),
            ("FIFA 24", "Football simulation game", 3999),
            ("Call of Duty: Modern Warfare III", "First-person shooter", 4499),
        ]

        # Insert products
        for name, desc, price in products:
            cursor.execute("""
                INSERT INTO products(name, description, price, active, created_at, updated_at)
                VALUES (?, ?, ?, 1, ?, ?)
            """, (name, desc, price, datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()))

        print(f"Added {len(products)} products")
        
        # Get product IDs
        cursor.execute("SELECT id, name FROM products")
        product_map = {row[1]: row[0] for row in cursor.fetchall()}
        
        # Sample keys for each product
        import hashlib
        sample_keys = {
            "Grand Theft Auto V Premium Edition": [
                "GTA5-XXXX-YYYY-ZZZZ-AAAA",
                "GTA5-BBBB-CCCC-DDDD-EEEE",
                "GTA5-FFFF-GGGG-HHHH-IIII",
                "GTA5-JJJJ-KKKK-LLLL-MMMM",
                "GTA5-NNNN-OOOO-PPPP-QQQQ",
            ],
            "Red Dead Redemption 2": [
                "RDR2-XXXX-YYYY-ZZZZ-AAAA",
                "RDR2-BBBB-CCCC-DDDD-EEEE",
                "RDR2-FFFF-GGGG-HHHH-IIII",
            ],
            "Cyberpunk 2077": [
                "CYBER-XXXX-YYYY-ZZZZ-AAAA",
                "CYBER-BBBB-CCCC-DDDD-EEEE",
                "CYBER-FFFF-GGGG-HHHH-IIII",
            ],
            "Elden Ring": [
                "ELDEN-XXXX-YYYY-ZZZZ-AAAA",
                "ELDEN-BBBB-CCCC-DDDD-EEEE",
            ],
            "God of War Ragnarok": [
                "GOWR-XXXX-YYYY-ZZZZ-AAAA",
                "GOWR-BBBB-CCCC-DDDD-EEEE",
            ],
            "Minecraft Java Edition": [
                "MINE-XXXX-YYYY-ZZZZ-AAAA",
                "MINE-BBBB-CCCC-DDDD-EEEE",
                "MINE-FFFF-GGGG-HHHH-IIII",
                "MINE-JJJJ-KKKK-LLLL-MMMM",
            ],
            "FIFA 24": [
                "FIFA24-XXXX-YYYY-ZZZZ-AAAA",
                "FIFA24-BBBB-CCCC-DDDD-EEEE",
            ],
            "Call of Duty: Modern Warfare III": [
                "CODMW3-XXXX-YYYY-ZZZZ-AAAA",
                "CODMW3-BBBB-CCCC-DDDD-EEEE",
            ],
        }
        
        # Insert keys
        total_keys = 0
        for product_name, keys in sample_keys.items():
            if product_name in product_map:
                product_id = product_map[product_name]
                for key in keys:
                    key_hash = hashlib.sha256(key.encode()).hexdigest()
                    key_enc = fernet.encrypt(key.encode())
                    cursor.execute("""
                        INSERT INTO keys(product_id, key_enc, key_hash, status, created_at)
                        VALUES (?, ?, ?, 'unused', ?)
                    """, (product_id, key_enc, key_hash, datetime.now(timezone.utc).isoformat()))
                    total_keys += 1
        
        print(f"Added {total_keys} game keys")
        
        # Create a sample customer user
        customer_email = "customer@vanta.com"
        cursor.execute("SELECT 1 FROM users WHERE email=?", (customer_email,))
        if not cursor.fetchone():
            cursor.execute("""
                INSERT INTO users(email, name, pw, role, active, balance, created_at)
                VALUES (?, ?, ?, 'customer', 1, 5000, ?)
            """, (customer_email, "Vanta Gamer", generate_password_hash("customer123"), datetime.now(timezone.utc).isoformat()))
            print(f"Created customer user: {customer_email} / customer123")

            # Add some sample transactions for the customer
            cursor.execute("SELECT id FROM users WHERE email=?", (customer_email,))
            user_id = cursor.fetchone()[0]

            # Add ledger entries
            cursor.execute("""
                INSERT INTO ledger(user_id, type, amount, ref, created_at)
                VALUES (?, 'topup', 5000, 'INITIAL', ?)
            """, (user_id, datetime.now(timezone.utc).isoformat()))

            # Make a sample purchase
            if product_map:
                first_product_id = list(product_map.values())[0]
                cursor.execute("""
                    INSERT INTO orders(ref, user_id, product_id, price, status, created_at)
                    VALUES (?, ?, ?, ?, 'completed', ?)
                """, ("ORD-SAMPLE", user_id, first_product_id, 1499, datetime.now(timezone.utc).isoformat()))

                # Deduct balance
                cursor.execute("UPDATE users SET balance = balance - 1499 WHERE id = ?", (user_id,))

                # Add ledger entry for purchase
                cursor.execute("""
                    INSERT INTO ledger(user_id, type, amount, ref, created_at)
                    VALUES (?, 'purchase', -1499, 'ORD-SAMPLE', ?)
                """, (user_id, datetime.now(timezone.utc).isoformat()))

                print(f"Added sample purchase for customer")
        
        # Create some sample top-up requests
        cursor.execute("SELECT id FROM users WHERE email=?", (customer_email,))
        user_id = cursor.fetchone()[0]
        
        topups = [
            (500, "UTR123456789"),
            (1000, "UTR987654321"),
        ]
        
        for amount, utr in topups:
            cursor.execute("""
                INSERT INTO topups(user_id, amount, utr, status, created_at)
                VALUES (?, ?, ?, 'pending', ?)
            """, (user_id, amount, utr, datetime.now(timezone.utc).isoformat()))
        
        print(f"Added {len(topups)} pending top-up requests")
        
        # Commit all changes
        conn.commit()

        print("\n" + "="*50)
        print("Sample data populated successfully!")
        print("="*50)
        print("\nTest Accounts:")
        print("   Admin: admin@example.com / admin123")
        print("   Customer: customer@vanta.com / customer123")
        print("\nCustomer balance: Rs.3501")
        print("Products: 8")
        print("Total Keys: " + str(total_keys))
        print("\nVisit: http://127.0.0.1:5000")
        print("="*50)

    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    if os.path.exists(DB_PATH):
        populate_data()
    else:
        print("Database not found. Run the app first to create the database.")
