import streamlit as st
from cryptography.fernet import Fernet
import base64
import hashlib

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
    encrypted_filename = filename + ".encrypted"
    with open(encrypted_filename, "wb") as encrypted_file:
        encrypted_file.write(encrypted)

    return encrypted_filename

# Function to decrypt a file
def decrypt_file(filename, key):
    fernet = Fernet(key)  # Initialize Fernet with the given key

    # Read the encrypted file
    with open(filename, "rb") as file:
        encrypted = file.read()

    # Decrypt the file content
    decrypted = fernet.decrypt(encrypted)

    # Write the decrypted content to a new file, removing the ".encrypted" extension
    decrypted_filename = filename[:-10]
    with open(decrypted_filename, "wb") as decrypted_file:
        decrypted_file.write(decrypted)

    return decrypted_filename

# Function to convert text to binary
def text_to_binary(text):
    return ' '.join(format(ord(char), '08b') for char in text)

# Function to convert binary to text
def binary_to_text(binary_string):
    binary_string = binary_string.replace(" ", "")
    if len(binary_string) % 8 != 0:
        raise ValueError("Invalid binary string length. It should be a multiple of 8.")
    binary_values = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    ascii_characters = [chr(int(binary, 2)) for binary in binary_values]
    return ''.join(ascii_characters)

# Streamlit app
st.title("Encryption/Decryption & Binary Converter")

# Navigation
option = st.sidebar.selectbox(
    "Choose an option",
    ("Encryption/Decryption", "Binary Converter")
)

if option == "Encryption/Decryption":
    st.header("File Encryption and Decryption")

    operation = st.selectbox("Choose an operation", ["Encrypt", "Decrypt"])

    uploaded_file = st.file_uploader("Choose a file", type=['txt', 'bin', 'encrypted'])

    password = st.text_input("Enter a password", type="password")

    if uploaded_file and password:
        key = generate_key_from_password(password)

        with open(uploaded_file.name, "wb") as f:
            f.write(uploaded_file.getbuffer())

        if operation == "Encrypt":
            encrypted_filename = encrypt_file(uploaded_file.name, key)
            st.success(f"File has been encrypted and saved as {encrypted_filename}")
            st.download_button(
                label="Download Encrypted File",
                data=open(encrypted_filename, "rb").read(),
                file_name=encrypted_filename
            )

        elif operation == "Decrypt":
            if uploaded_file.name.endswith(".encrypted"):
                try:
                    decrypted_filename = decrypt_file(uploaded_file.name, key)
                    st.success(f"File has been decrypted and saved as {decrypted_filename}")
                    st.download_button(
                        label="Download Decrypted File",
                        data=open(decrypted_filename, "rb").read(),
                        file_name=decrypted_filename
                    )
                except Exception as e:
                    st.error(f"Decryption failed: {e}")
            else:
                st.error("Selected file does not appear to be encrypted.")

elif option == "Binary Converter":
    st.header("Text to Binary and Binary to Text Converter")

    conversion_type = st.selectbox("Choose a conversion type", ["Text to Binary", "Binary to Text"])

    if conversion_type == "Text to Binary":
        text = st.text_area("Enter text to convert to binary")
        if st.button("Convert"):
            if text:
                binary = text_to_binary(text)
                st.success(f"Binary Representation: {binary}")
            else:
                st.error("Please enter some text to convert.")

    elif conversion_type == "Binary to Text":
        binary_string = st.text_area("Enter binary to convert to text")
        if st.button("Convert"):
            try:
                if binary_string:
                    text = binary_to_text(binary_string)
                    st.success(f"Text Representation: {text}")
                else:
                    st.error("Please enter a binary string to convert.")
            except ValueError as e:
                st.error(f"Conversion failed: {e}")
