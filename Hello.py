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

# Define the list of available .py files with their respective names and functions
file_functions = {
    "BlockCipher_XOR.py": (BlockCipher_XOR.block_cipher_xor, "Block Cipher XOR"),
    "XOR_Cipher.py": (None, "XOR Cipher"),
    "Caesar_Cipher.py": (None, "Caesar Cipher"),
    "Hashing_function.py": (Hashing_function.main, "Hashing Function"),
    "SecureChatwithDiffie-Hellman.py": (None, "Secure Chat with Diffie-Hellman")
}

# Display buttons for each .py file in the sidebar
st.sidebar.title("📚 Pages")
selected_page = st.sidebar.radio("", [name for function, name in file_functions.values()], index=0)

# Show content of the selected page
st.title("🚀 Streamlit Page Navigator")

if selected_page in [name for function, name in file_functions.values()]:
    function_to_execute = [function for function, name in file_functions.values() if name == selected_page][0]
    if function_to_execute:
        st.markdown(f"## {selected_page}")
        function_to_execute()
    else:
        st.write("This page does not have an executable function.")
