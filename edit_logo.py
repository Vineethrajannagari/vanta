"""
Script to edit the logo image and change "GAMER" to "VANTA"
Requires: pip install Pillow
"""
from PIL import Image, ImageDraw, ImageFont
import os

def edit_logo(input_path, output_path, old_text="GAMER", new_text="VANTA"):
    """
    Edit the logo image to replace text
    """
    try:
        # Open the image
        img = Image.open(input_path)
        
        # Convert to RGB if necessary
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Get image dimensions
        width, height = img.size
        
        # Create a drawing object
        draw = ImageDraw.Draw(img)
        
        # Try to find a suitable font
        try:
            # Try to use a bold font
            font = ImageFont.truetype("arialbd.ttf", 60)
        except:
            try:
                font = ImageFont.truetype("arial.ttf", 60)
            except:
                # Use default font if Arial not available
                font = ImageFont.load_default()
        
        # Find the text position (this is approximate - you may need to adjust)
        # Looking for white text at the bottom of the image
        text_y = height - 80  # Adjust based on your image
        text_x = width // 2   # Center horizontally
        
        # Draw a black rectangle over the old text area to cover it
        # You may need to adjust these coordinates based on your image
        text_box_top = height - 100
        text_box_bottom = height - 20
        text_box_left = width // 2 - 150
        text_box_right = width // 2 + 150
        
        # Fill with dark red (matching the background)
        draw.rectangle([text_box_left, text_box_top, text_box_right, text_box_bottom],
                       fill=(80, 0, 0))
        
        # Draw the new text
        text_width = draw.textlength(new_text, font=font)
        text_x = (width - text_width) // 2
        
        # Draw black outline
        outline_width = 3
        for x_offset in range(-outline_width, outline_width + 1):
            for y_offset in range(-outline_width, outline_width + 1):
                if x_offset == 0 and y_offset == 0:
                    continue
                draw.text((text_x + x_offset, text_y + y_offset), new_text,
                        font=font, fill=(0, 0, 0))
        
        # Draw white text
        draw.text((text_x, text_y), new_text, font=font, fill=(255, 255, 255))
        
        # Save the edited image
        img.save(output_path)
        print(f"Logo edited successfully! Saved to: {output_path}")
        return True

    except Exception as e:
        print(f"Error editing logo: {e}")
        return False

def create_new_logo(output_path, text="VANTA"):
    """
    Create a new logo from scratch with the VANTA text
    """
    try:
        # Create a new image with dark red background
        width, height = 400, 400
        img = Image.new('RGB', (width, height), color=(80, 0, 0))
        
        draw = ImageDraw.Draw(img)
        
        # Try to load a font
        try:
            font = ImageFont.truetype("arialbd.ttf", 80)
        except:
            try:
                font = ImageFont.truetype("arial.ttf", 80)
            except:
                font = ImageFont.load_default()
        
        # Draw the text centered
        text_width = draw.textlength(text, font=font)
        text_x = (width - text_width) // 2
        text_y = height // 2 - 40
        
        # Draw black outline
        outline_width = 4
        for x_offset in range(-outline_width, outline_width + 1):
            for y_offset in range(-outline_width, outline_width + 1):
                if x_offset == 0 and y_offset == 0:
                    continue
                draw.text((text_x + x_offset, text_y + y_offset), text,
                        font=font, fill=(0, 0, 0))
        
        # Draw white text
        draw.text((text_x, text_y), text, font=font, fill=(255, 255, 255))
        
        # Save the image
        img.save(output_path)
        print(f"New logo created! Saved to: {output_path}")
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

    # Path to your original logo (update this)
    input_logo = "logo.png"  # Change this to your actual logo file name

    # Output path
    output_logo = "logo_vanta.png"

    # Try to edit existing logo if it exists
    if os.path.exists(input_logo):
        print(f"Editing existing logo: {input_logo}")
        success = edit_logo(input_logo, output_logo)
    else:
        print(f"Logo file not found: {input_logo}")
        print("Creating a new logo instead...")
        success = create_new_logo(output_logo)

    if success:
        print(f"\nDone! Your 'VANTA' logo is ready at: {output_logo}")
        print(f"You can now use this logo in your website")
