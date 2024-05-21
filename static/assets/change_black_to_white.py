from PIL import Image

# Load the image
image_path = "eyre.png"
img = Image.open(image_path)

# Ensure the image has an alpha channel
img = img.convert("RGBA")

# Get the image data
data = img.getdata()

# Create a new list to hold the modified image data
new_data = []

# Define the threshold
threshold = 50

# Loop through each pixel in the image data
for item in data:
    # Check if the pixel is below the threshold for red, green, and blue
    if item[0] < threshold and item[1] < threshold and item[2] < threshold:
        # Change to white but keep the original alpha value
        new_data.append((255, 255, 255, item[3]))
    else:
        # Otherwise, keep the original pixel
        new_data.append(item)

# Update image data with the modified data
img.putdata(new_data)

# Save the modified image
modified_image_path = "eyre-white.png"
img.save(modified_image_path)

print("Image processing complete. Modified image saved as", modified_image_path)
