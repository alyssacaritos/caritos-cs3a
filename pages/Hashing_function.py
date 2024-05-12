import streamlit as st
import hashlib

# Function to hash data based on selected hash mode
def hash_data(data, hash_mode):
    if hash_mode == "MD5":
        hasher = hashlib.md5()
    elif hash_mode == "SHA-1":
        hasher = hashlib.sha1()
    elif hash_mode == "SHA-256":
        hasher = hashlib.sha256()
    elif hash_mode == "SHA-512":
        hasher = hashlib.sha512()
    elif hash_mode == "SHA3-256":
        hasher = hashlib.sha3_256()
    elif hash_mode == "SHA3-512":
        hasher = hashlib.sha3_512()
    elif hash_mode == "BLAKE2b":
        hasher = hashlib.blake2b()
    elif hash_mode == "BLAKE2s":
        hasher = hashlib.blake2s()
    elif hash_mode == "SHA-384":
        hasher = hashlib.sha384()
    else:
        return "Invalid hashing mode"
    
    hasher.update(data)
    return hasher.hexdigest()

def main():
    # Main content area
    st.title("🔒 HASHING FUNCTION 🛠️")
    st.markdown("---")
    st.sidebar.title("📤 Choose Input Option")
    input_option = st.sidebar.radio("", ("📝 Text", "📂 File"))

    # Text input or file upload based on user choice
    data_input = ""
    if input_option == "📝 Text":
        data_input = st.text_area("Enter text to hash:", height=100, max_chars=2000)
    else:
        uploaded_file = st.file_uploader("Upload a file:")
        if uploaded_file is not None:
            data_input = uploaded_file.read()

    # Hash mode selection with colorful stickers
    hash_modes = ("MD5", "SHA-1", "SHA-256", "SHA-512", "SHA3-256", "SHA3-512", "BLAKE2b", "BLAKE2s", "SHA-384")
    hash_mode = st.sidebar.selectbox("Choose Hash Mode", hash_modes)

    # Hash button for processing with colorful design
    submit_button = st.button("🔍 Hash", key="hash_button")

    # If hash button is clicked and data input is not empty, perform hashing
    if submit_button and data_input:
        if isinstance(data_input, bytes):
            hashed_data = hash_data(data_input, hash_mode)
        else:
            hashed_data = hash_data(data_input.encode(), hash_mode)
        
        # Display the hashed data with colorful success message
        st.markdown("---")
        st.header("Result")
        st.success(f"**📑 Hashed data ({hash_mode}):**")
        st.code(hashed_data, language="plaintext")

if __name__ == "__main__":
    main()
