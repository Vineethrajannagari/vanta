"""
Generate high quality Free Fire panel assets and thumbnails
"""
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import os

UPLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOADS_DIR, exist_ok=True)

def create_card_image(filename, title, subtitle, tag, color1, color2):
    w, h = 640, 400
    img = Image.new("RGB", (w, h), (10, 14, 23))
    draw = ImageDraw.Draw(img)

    # Gradient background
    r1, g1, b1 = color1
    r2, g2, b2 = color2
    for y in range(h):
        factor = y / h
        r = int(10 + factor * (r1 * 0.25))
        g = int(14 + factor * (g1 * 0.25))
        b = int(23 + factor * (b1 * 0.25))
        draw.line([(0, y), (w, y)], fill=(r, g, b))

    # Grid lines
    for x in range(0, w, 32):
        draw.line([(x, 0), (x, h)], fill=(255, 255, 255, 15), width=1)
    for y in range(0, h, 32):
        draw.line([(0, y), (w, y)], fill=(255, 255, 255, 15), width=1)

    # Outer neon border
    draw.rounded_rectangle([6, 6, w - 7, h - 7], radius=18, outline=color1, width=3)

    # Fonts
    try:
        f_title = ImageFont.truetype("arialbd.ttf", 36)
        f_sub = ImageFont.truetype("arialbd.ttf", 24)
        f_tag = ImageFont.truetype("arialbd.ttf", 16)
        f_watermark = ImageFont.truetype("arialbd.ttf", 14)
    except:
        f_title = ImageFont.load_default()
        f_sub = ImageFont.load_default()
        f_tag = ImageFont.load_default()
        f_watermark = ImageFont.load_default()

    # Tag badge at top right
    tag_w = draw.textlength(tag, font=f_tag)
    tag_bg = [w - tag_w - 40, 24, w - 20, 52]
    draw.rounded_rectangle(tag_bg, radius=10, fill=color1)
    draw.text((w - tag_w - 30, 29), tag, font=f_tag, fill=(0, 0, 0))

    # Free Fire Badge at top left
    draw.rounded_rectangle([20, 24, 150, 52], radius=10, fill=(20, 25, 38), outline=color1, width=1)
    draw.text((32, 29), "🔥 FREE FIRE", font=f_tag, fill=color1)

    # Center Title & Subtitle
    # Glow effect behind title
    for r_offset in range(12, 0, -3):
        draw.text((38, 150), title, font=f_title, fill=color1)

    draw.text((40, 150), title, font=f_title, fill=(255, 255, 255))
    draw.text((40, 205), subtitle, font=f_sub, fill=color2)

    # Bottom feature bar
    draw.line([(40, 290), (w - 40, 290)], fill=(255, 255, 255, 40), width=1)
    features = "✓ AUTO-UPDATE  •  ✓ NO BAN  •  ✓ INSTANT KEY"
    draw.text((40, 310), features, font=f_watermark, fill=(160, 175, 200))
    draw.text((40, 340), "VANTA FF OFFICIAL VIP PANEL LICENSE", font=f_watermark, fill=color1)

    out_path = os.path.join(UPLOADS_DIR, filename)
    img.save(out_path, "PNG")
    print(f"Generated {out_path}")

def create_store_banner():
    w, h = 1200, 320
    img = Image.new("RGB", (w, h), (8, 12, 20))
    draw = ImageDraw.Draw(img)

    # Fiery neon gradient
    for x in range(w):
        factor = x / w
        r = int(25 + factor * 70)
        g = int(10 + factor * 25)
        b = int(40 + (1 - factor) * 40)
        draw.line([(x, 0), (x, h)], fill=(r, g, b))

    # Grid overlay
    for x in range(0, w, 40):
        draw.line([(x, 0), (x, h)], fill=(255, 107, 0, 20), width=1)
    for y in range(0, h, 40):
        draw.line([(0, y), (w, y)], fill=(255, 107, 0, 20), width=1)

    # Border
    draw.rounded_rectangle([8, 8, w - 9, h - 9], radius=20, outline=(255, 107, 0), width=4)

    try:
        f_hero = ImageFont.truetype("arialbd.ttf", 52)
        f_sub = ImageFont.truetype("arialbd.ttf", 26)
        f_tag = ImageFont.truetype("arialbd.ttf", 18)
    except:
        f_hero = ImageFont.load_default()
        f_sub = ImageFont.load_default()
        f_tag = ImageFont.load_default()

    # Draw Banner Elements
    draw.rounded_rectangle([50, 40, 260, 75], radius=12, fill=(255, 107, 0))
    draw.text((65, 46), "🔥 FF OB45 READY", font=f_tag, fill=(0, 0, 0))

    draw.text((50, 100), "FREE FIRE VIP PANELS & KEYS", font=f_hero, fill=(255, 255, 255))
    draw.text((50, 175), "⚡ Instant Key Delivery  •  🛡️ Main ID Safe  •  📱 Android & iOS Root/Non-Root", font=f_sub, fill=(0, 229, 255))
    draw.text((50, 225), "Automated 24/7 Server Verification & 1-Click Key Redemption Vault", font=f_tag, fill=(255, 200, 120))

    # Right side badge
    draw.rounded_rectangle([w - 320, 60, w - 50, 240], radius=16, fill=(15, 20, 32), outline=(0, 229, 255), width=2)
    draw.text((w - 295, 85), "VANTA FF VIP", font=f_sub, fill=(255, 107, 0))
    draw.text((w - 295, 125), "★ 10,000+ Keys", font=f_tag, fill=(255, 255, 255))
    draw.text((w - 295, 155), "★ 100% Anti-Blacklist", font=f_tag, fill=(0, 229, 255))
    draw.text((w - 295, 185), "★ 24/7 Fast UPI Topup", font=f_tag, fill=(16, 185, 129))

    out_path = os.path.join(UPLOADS_DIR, "ff_banner.png")
    img.save(out_path, "PNG")
    print(f"Generated {out_path}")

if __name__ == "__main__":
    create_store_banner()
    create_card_image("ff_vip_24h.png", "VIP PANEL (24H PASS)", "1 DAY KEY • ALL MODES", "⚡ 24 HOURS", (255, 107, 0), (255, 200, 50))
    create_card_image("ff_vip_7d.png", "VIP PRO PANEL (7 DAYS)", "WEEKLY PASS • RANK PUSH", "📅 7 DAYS", (0, 229, 255), (100, 200, 255))
    create_card_image("ff_vip_30d.png", "VIP GOD PANEL (30 DAYS)", "MONTHLY PASS • AUTO-UPDATE", "🌟 30 DAYS", (168, 85, 247), (220, 150, 255))
    create_card_image("ff_headshot.png", "AUTO HEADSHOT & AIMLOCK", "DRAG AIM 99% • RECOIL 0", "🎯 AIMLOCK", (255, 71, 87), (255, 150, 150))
    create_card_image("ff_esp.png", "ESP & RADAR LOCATION", "NAME • HP • SKELETON • LOOT", "📡 ESP RADAR", (16, 185, 129), (100, 255, 180))
    create_card_image("ff_streamer.png", "STREAMER SAFE BYPASS", "ANTI-RECORD • CLEAN VIEW", "🛡️ STREAM SAFE", (56, 189, 248), (150, 225, 255))
    create_card_image("ff_ios.png", "iOS & IPAD EXTERNAL VIP", "NO JAILBREAK • 120 FPS", "🍎 iOS & IPAD", (245, 158, 11), (255, 215, 0))
    create_card_image("ff_lifetime.png", "LIFETIME GOD PANEL", "PERMANENT PASS • ALL PATCHES", "👑 LIFETIME", (236, 72, 153), (255, 180, 220))
