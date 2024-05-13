import streamlit as st
import importlib.util
from streamlit.logger import get_logger
from pages import BlockCipher_XOR, Hashing_function, XOR_Cipher, Caesar_Cipher, SecureChatwithDiffieHellman  

LOGGER = get_logger(__name__)

# Function to execute content of .py files
def execute_py_file(file_path):
    spec = importlib.util.spec_from_file_location("module", file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

# Define the list of available .py files with their respective names, functions, and emojis
file_functions = {
    "BlockCipher_XOR.py": (BlockCipher_XOR.block_cipher_xor, "Block Cipher XOR", "🔒"),
    "XOR_Cipher.py": (XOR_Cipher.main, "XOR Cipher", "🔑"),
    "Caesar_Cipher.py": (Caesar_Cipher.main, "Caesar Cipher", "🎭"),
    "Hashing_function.py": (Hashing_function.main, "Hashing Function", "🔗"),
    "SecureChatwithDiffie-Hellman.py": (SecureChatwithDiffieHellman.main, "Secure Chat with Diffie-Hellman", "🔑🔒")
}

# Debugging prints to check the structure of file_functions dictionary
print("file_functions:", file_functions)

# Extract the names of the pages
page_names = [name for function, name, _ in file_functions.values() if function is not None]

# Display the introduction text and a checkbox for viewing text only
st.title(" ♨️ Applied Cryptography ")
show_text_only = st.checkbox("View Text Only")

if show_text_only:
    st.write("""
        
        **📝Author**: 
            
            Caritos, Alyssa P.
            Maraño, Mary France
            Aguilar, Troy

        The Applied Cryptography Application project aims to develop a simple application that implements various cryptographic techniques to secure communication, data, and information exchange. Cryptography is the science of encoding and decoding messages to protect their confidentiality, integrity, and authenticity. 

        This application covers the following cryptographic techniques:
        
        - **Symmetric Encryption and Decryption**: In symmetric encryption, the same key is used for both encryption and decryption. It's fast and efficient but requires secure key distribution. Examples include the Block Cipher XOR and XOR Cipher.

        - **Asymmetric Encryption and Decryption**: Asymmetric encryption uses a pair of keys - public and private keys. The public key is used for encryption, while the private key is used for decryption. It provides secure key exchange but is slower compared to symmetric encryption. An example is the Secure Chat with Diffie-Hellman.

        - **Hashing Function**: Hashing functions take an input (or 'message') and return a fixed-size string of bytes. The output is typically a hash value. Hash functions are commonly used in various aspects of cryptography, including password storage and digital signatures.
        
        The application will provide a user-friendly interface that allows users to encrypt, decrypt, and hash messages/files using different cryptographic algorithms 🤖.
        """)
else:
    # Display buttons for each .py file in the main content area
    selected_page = st.selectbox("Select a Page", page_names)

    # Show content of the selected page
    if selected_page:
        function_to_execute, _, emoji = [values for values in file_functions.values() if values[1] == selected_page][0]
        if function_to_execute:
            st.markdown(f"## {selected_page} {emoji}")
            function_to_execute()
        else:
            st.write("This page does not have an executable function.")
