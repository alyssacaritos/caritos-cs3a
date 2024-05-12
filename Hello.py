import streamlit as st
import importlib.util
import os
from streamlit.logger import get_logger
from pages import BlockCipher_XOR 
from pages import Hashing_function # Importing the Block Cipher file

LOGGER = get_logger(__name__)

# Function to execute content of .py files
def execute_py_file(file_path):
    spec = importlib.util.spec_from_file_location("module", file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

# Define the list of available .py files
file_paths = [
    "pages/BlockCipher_XOR.py",
    "pages/XOR_Cipher.py",
    "pages/Caesar_Cipher.py",
    "pages/Hashing_function.py",
    "pages/SecureChatwithDiffie-Hellman.py"
]

# Display buttons for each .py file
for file_path in file_paths:
    file_name = os.path.basename(file_path)  # Extract the file name from the file path
    if st.button(file_name):
        if file_path == "pages/BlockCipher_XOR.py":
            BlockCipher_XOR.block_cipher_xor()
        elif file_path == "pages/Hashing_function.py":
            Hashing_function.main()  # Call the Block Cipher function directly
        else:
            execute_py_file(file_path)
