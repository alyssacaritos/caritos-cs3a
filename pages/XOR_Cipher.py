import streamlit as st

# Define XOR encryption and decryption functions
def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key."""
    ciphertext = bytearray()
    xor_operations = []
    for i in range(len(plaintext)):
        xor_result = plaintext[i] ^ key[i % len(key)]
        ciphertext.append(xor_result)
        xor_operations.append((plaintext[i], key[i % len(key)], xor_result))
    return ciphertext, xor_operations

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    decrypted = bytearray()
    xor_operations = []
    for i in range(len(ciphertext)):
        xor_result = ciphertext[i] ^ key[i % len(key)]
        decrypted.append(xor_result)
        xor_operations.append((ciphertext[i], key[i % len(key)], xor_result))
    return decrypted, xor_operations

# Define function to display encryption/decryption results
def display_results(ciphertext, decrypted, xor_encrypt_operations, xor_decrypt_operations):
    st.subheader("Results")
    col1, col2 = st.columns(2)
    with col1:
        st.write("Ciphertext:")
        st.code(ciphertext.decode(), language='plaintext')
        
        st.subheader("XOR Operations (Encryption) 🔒")
        for plaintext_byte, key_byte, xor_result in xor_encrypt_operations:
            st.write(f"Plaintext byte: {plaintext_byte:08b} = {chr(plaintext_byte)}")
            st.write(f"Key byte:       {key_byte:08b} = {chr(key_byte)}")
            st.write(f"XOR result:     {xor_result:08b} = {chr(xor_result)}")
            st.write("--------------------")
            
    with col2:
        st.write("Decrypted:")
        st.code(decrypted.decode(), language='plaintext')

        st.subheader("XOR Operations (Decryption) 🔓")
        for ciphertext_byte, key_byte, xor_result in xor_decrypt_operations:
            st.write(f"Ciphertext byte: {ciphertext_byte:08b} = {chr(ciphertext_byte)}")
            st.write(f"Key byte:         {key_byte:08b} = {chr(key_byte)}")
            st.write(f"XOR result:       {xor_result:08b} = {chr(xor_result)}")
            st.write("--------------------")

# Streamlit app UI
def main():
    st.title("XOR Cipher 🛡️")
    st.markdown("Encrypt and Decrypt using XOR Cipher with a Key")

# Add a button in the sidebar to choose input method
    st.sidebar.title("📥 Choose Input Option")
    input_method = st.sidebar.radio("", ("📝 Text", "📂 File"))

    with st.form("xor_cipher_form"):
        st.subheader("Encrypt and Decrypt")
        if input_method == "📂 File":
            uploaded_file = st.file_uploader("Upload a text file 📁", type=["txt"])
            plaintext = ""
        else:
            uploaded_file = None
            plaintext = st.text_area("Enter Plain Text:", max_chars=200)
        key = st.text_input("Enter Key 🔑:")
        submitted = st.form_submit_button("Encrypt & Decrypt")

# Process submitted form
    if submitted:
        if not key:
            st.error("Please provide a key.")
        else:
            if uploaded_file is not None:
                plaintext = uploaded_file.read().decode()
        
            if not plaintext:
                st.error("Please provide a text file or enter plaintext.")
            else:
                plaintext_bytes = plaintext.encode()
                key_bytes = key.encode()
            
                if len(plaintext_bytes) < len(key_bytes):
                    st.error("Plaintext length should be equal or greater than the length of the key.")
                elif plaintext_bytes == key_bytes:
                    st.error("Plaintext should not be equal to the key.")
                else:
                    ciphertext, xor_encrypt_operations = xor_encrypt(plaintext_bytes, key_bytes)
                    decrypted, xor_decrypt_operations = xor_decrypt(ciphertext, key_bytes)
                    display_results(ciphertext, decrypted, xor_encrypt_operations, xor_decrypt_operations)

if __name__ == "__main__":
    main()
