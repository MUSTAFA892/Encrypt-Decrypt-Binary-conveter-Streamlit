from cryptography.fernet import Fernet
import getpass  # Used for securely getting the password input
import base64
import hashlib  # Used for generating the key from the password

# Function to generate a key from a password
def generate_key_from_password(password):
    password_bytes = password.encode()  # Convert the password to bytes
    key = hashlib.sha256(password_bytes).digest()  # Hash the password to get a 32-byte key
    return base64.urlsafe_b64encode(key)  # Encode the key in base64 to make it URL-safe

# Function to encrypt a file
def encrypt_file(filename, key):
    fernet = Fernet(key)  # Initialize Fernet with the given key

    # Read the original file
    with open(filename, "rb") as file:
        original = file.read()

    # Encrypt the file content
    encrypted = fernet.encrypt(original)

    # Write the encrypted content to a new file
    with open(filename + ".encrypted", "wb") as encrypted_file:
        encrypted_file.write(encrypted)
    
    # Print a success message
    print(f"File {filename} has been encrypted and saved as {filename}.encrypted")

# Function to decrypt a file
def decrypt_file(filename, key):
    fernet = Fernet(key)  # Initialize Fernet with the given key

    # Read the encrypted file
    with open(filename, "rb") as file:
        encrypted = file.read()

    # Decrypt the file content
    decrypted = fernet.decrypt(encrypted)

    # Write the decrypted content to a new file, removing the ".encrypted" extension
    with open(filename[:-10], "wb") as decrypted_file:
        decrypted_file.write(decrypted)
    
    # Print a success message
    print(f"File {filename} has been decrypted and saved as {filename[:-10]}")

# Main function to handle user input and call the appropriate function
if __name__ == "__main__":
    filename = "sample.txt"  # The name of the file to be encrypted/decrypted

    # Prompt the user to choose between encrypting and decrypting the file
    choice = input("Would you like to (e)ncrypt or (d)ecrypt the file? ")

    # Get the password from the user securely
    password = getpass.getpass("Enter the password: ")
    key = generate_key_from_password(password)  # Generate the key from the password

    # Perform the chosen operation
    if choice.lower() == 'e':
        encrypt_file(filename, key)  # Encrypt the file
    elif choice.lower() == 'd':
        encrypted_filename = filename + ".encrypted"  # The expected name of the encrypted file
        decrypt_file(encrypted_filename, key)  # Decrypt the file
    else:
        # Print an error message if the choice is invalid
        print("Invalid choice. Please select 'e' to encrypt or 'd' to decrypt.")
