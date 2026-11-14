"""
Create a stylized gaming logo for VANTA
"""
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import os

def create_vanta_logo(output_path="vanta_logo.png"):
    """
    Create a stylized gaming logo with dark theme and glowing effects
    """
    try:
        # Create image with dark gradient background
        width, height = 500, 500
        img = Image.new('RGB', (width, height), color=(15, 15, 20))

        draw = ImageDraw.Draw(img)

        # Create gradient effect
        for y in range(height):
            # Dark red to black gradient
            r = int(80 - (y / height) * 60)
            g = int(10 - (y / height) * 10)
            b = int(15 - (y / height) * 15)
            draw.line([(0, y), (width, y)], fill=(r, g, b))

        # Add subtle grid pattern
        for i in range(0, width, 20):
            draw.line([(i, 0), (i, height)], fill=(30, 30, 40), width=1)
        for i in range(0, height, 20):
            draw.line([(0, i), (width, i)], fill=(30, 30, 40), width=1)

        # Try to load a bold font
        try:
            font_large = ImageFont.truetype("arialbd.ttf", 120)
            font_small = ImageFont.truetype("arial.ttf", 30)
        except:
            try:
                font_large = ImageFont.truetype("arial.ttf", 120)
                font_small = ImageFont.truetype("arial.ttf", 30)
            except:
                font_large = ImageFont.load_default()
                font_small = ImageFont.load_default()

        # Draw "VANTA" text with glow effect
        text = "VANTA"
        text_width = draw.textlength(text, font=font_large)
        text_x = (width - text_width) // 2
        text_y = height // 2 - 60

        # Draw glow layers (red glow)
        for glow_radius in range(30, 10, -5):
            for x_offset in range(-glow_radius, glow_radius + 1):
                for y_offset in range(-glow_radius, glow_radius + 1):
                    if x_offset == 0 and y_offset == 0:
                        continue
                    alpha = int(100 * (1 - glow_radius / 30))
                    draw.text((text_x + x_offset, text_y + y_offset), text,
                            font=font_large, fill=(255, 50, 50))

        # Draw black outline
        outline_width = 5
        for x_offset in range(-outline_width, outline_width + 1):
            for y_offset in range(-outline_width, outline_width + 1):
                if x_offset == 0 and y_offset == 0:
                    continue
                draw.text((text_x + x_offset, text_y + y_offset), text,
                        font=font_large, fill=(0, 0, 0))

        # Draw white text
        draw.text((text_x, text_y), text, font=font_large, fill=(255, 255, 255))

        # Add "GAME KEYS STORE" subtitle
        subtitle = "GAME KEYS STORE"
        subtitle_width = draw.textlength(subtitle, font=font_small)
        subtitle_x = (width - subtitle_width) // 2
        subtitle_y = text_y + 140

        # Draw subtitle outline
        for x_offset in range(-2, 3):
            for y_offset in range(-2, 3):
                if x_offset == 0 and y_offset == 0:
                    continue
                draw.text((subtitle_x + x_offset, subtitle_y + y_offset), subtitle,
                        font=font_small, fill=(0, 0, 0))

        # Draw subtitle text (cyan color)
        draw.text((subtitle_x, subtitle_y), subtitle, font=font_small, fill=(0, 212, 255))

        # Add decorative elements (gaming controller icon approximation)
        # Draw a simple controller shape
        controller_x = width // 2
        controller_y = text_y - 120
        controller_width = 80
        controller_height = 50

        # Controller body
        draw.ellipse([controller_x - controller_width//2, controller_y - controller_height//2,
                      controller_x + controller_width//2, controller_y + controller_height//2],
                     fill=(50, 50, 60), outline=(0, 212, 255), width=3)

        # Controller buttons
        draw.ellipse([controller_x - 20, controller_y - 10, controller_x - 10, controller_y + 1],
                     fill=(255, 50, 50))
        draw.ellipse([controller_x + 10, controller_y - 10, controller_x + 20, controller_y + 1],
                     fill=(255, 50, 50))
        draw.ellipse([controller_x - 5, controller_y + 10, controller_x + 5, controller_y + 20],
                     fill=(0, 212, 255))

        # Apply slight blur for glow effect
        img = img.filter(ImageFilter.SMOOTH)

        # Save the image
        img.save(output_path)
        print(f"VANTA gaming logo created! Saved to: {output_path}")
        return True

    except Exception as e:
        print(f"Error creating logo: {e}")
        return False

if __name__ == "__main__":
    # Check if Pillow is installed
    try:
        from PIL import Image
    except ImportError:
        print("Pillow is not installed. Install it with: pip install Pillow")
        exit(1)

    # Create the logo
    output_logo = "vanta_gaming_logo.png"
    success = create_vanta_logo(output_logo)

    if success:
        print(f"\nDone! Your VANTA gaming logo is ready at: {output_logo}")
        print("You can now use this as your store logo/banner")
