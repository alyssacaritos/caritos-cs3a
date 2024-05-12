import streamlit as st
import importlib.util
import os
from streamlit.logger import get_logger
from pages import BlockCipher_XOR, Hashing_function  # Importing the Block Cipher and Hashing function files

LOGGER = get_logger(__name__)

# Function to execute content of .py files
def execute_py_file(file_path):
    spec = importlib.util.spec_from_file_location("module", file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

# Define the list of available .py files with their respective names and previews
file_previews = {
    "BlockCipher_XOR.py": ("Block Cipher XOR", "Preview text or image for Block Cipher XOR"),
    "XOR_Cipher.py": ("XOR Cipher", "Preview text or image for XOR Cipher"),
    "Caesar_Cipher.py": ("Caesar Cipher", "Preview text or image for Caesar Cipher"),
    "Hashing_function.py": ("Hashing Function", "Preview text or image for Hashing Function"),
    "SecureChatwithDiffie-Hellman.py": ("Secure Chat with Diffie-Hellman", "Preview text or image for Secure Chat with Diffie-Hellman")
}

# Display buttons for each .py file in the sidebar
st.sidebar.title("📚 Pages")
selected_page = st.sidebar.radio("", list(file_previews.keys()), format_func=lambda x: file_previews[x][0])

# Show preview and execute the selected page
st.title("🚀 Streamlit Page Navigator")

if selected_page in file_previews:
    page_name, preview_text = file_previews[selected_page]
    st.markdown(f"## {page_name}")
    st.write(preview_text)
    if st.button("Open Page"):
        if selected_page == "Hashing_function.py":
            Hashing_function.main()
        elif selected_page == "BlockCipher_XOR.py":
            BlockCipher_XOR.block_cipher_xor()
        else:
            execute_py_file(os.path.join("pages", selected_page))
