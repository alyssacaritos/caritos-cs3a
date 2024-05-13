import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import base64

# Streamlit app
def main():
    st.title("🔒RSA Encryption and Decryption")

    # Initialize key variables
    public_key = None
    private_key = None

    # Ask the user for the plaintext message
    plaintext = st.text_input("🔤 Enter the message to encrypt", "")

    # Key size selection
    key_size = st.selectbox("🔑 Select key size", [1024, 2048, 4096])

    # Submit button for key generation and encryption
    if st.button("🔒 Generate Key Pair & Encrypt"):
        # Generate RSA key pair
        key = RSA.generate(key_size)

        # Save keys to files
        public_key_filename = "public_key.pem"
        private_key_filename = "private_key.pem"
        with open(public_key_filename, "wb") as public_key_file:
            public_key_file.write(key.publickey().exportKey())
        with open(private_key_filename, "wb") as private_key_file:
            private_key_file.write(key.exportKey())

        # Encrypt the message using RSA public key
        if plaintext:
            cipher_rsa = PKCS1_OAEP.new(key.publickey())
            ciphertext = cipher_rsa.encrypt(plaintext.encode())

            # Save encrypted message to a file
            with open("encrypted_message.txt", "wb") as encrypted_message_file:
                encrypted_message_file.write(ciphertext)

            st.success("📝 Encrypted message has been saved to 'encrypted_message.txt'")

            # Display encrypted message
            st.write("🔒 Encrypted message:", ciphertext.hex())

            # Set keys for decryption
            public_key = key.publickey()
            private_key = key

            # Automatically download encrypted message
            st.markdown(get_binary_file_downloader_html("encrypted_message.txt", '📥 Encrypted Message', 'encrypted_message.txt'), unsafe_allow_html=True)

            # Automatically download public key
            st.markdown(get_binary_file_downloader_html(public_key_filename, '🔑 Public Key', 'public_key.pem'), unsafe_allow_html=True)

            # Automatically download private key
            st.markdown(get_binary_file_downloader_html(private_key_filename, '🔑 Private Key', 'private_key.pem'), unsafe_allow_html=True)

    # Decryption section
    st.markdown("---")
    st.title("🔓 Decryption")

    # Upload encrypted message file
    st.write("📤 Upload encrypted message file:")
    encrypted_message_file = st.file_uploader("📁 Choose a file", type=["txt"])
    if encrypted_message_file is not None:
        encrypted_message_content = encrypted_message_file.getvalue()

        # Load private key if not generated
        if private_key is None:
            if os.path.isfile("private_key.pem"):
                with open("private_key.pem", "rb") as private_key_file:
                    private_key = RSA.importKey(private_key_file.read())
            else:
                st.error("❌ Private key not found. Please upload the private key file.")
                return

        # Decrypt the message using RSA private key
        if private_key:
            try:
                decipher_rsa = PKCS1_OAEP.new(private_key)
                decrypted_message = decipher_rsa.decrypt(encrypted_message_content)
                st.success("🔓 Decryption successful!")
                st.write("🔤 Decrypted message:", decrypted_message.decode())
            except Exception as e:
                st.error("❌ Error during decryption:")
                st.error("❌ You should Generate the key first:")
                st.error(e)

def get_binary_file_downloader_html(bin_file, file_label='File', file_name='file.txt'):
    with open(bin_file, 'rb') as f:
        data = f.read()
    b64 = base64.b64encode(data).decode()
    href = f'<a href="data:file/txt;base64,{b64}" download="{file_name}">Download {file_label}</a>'
    return href

if __name__ == "__main__":
    main()
