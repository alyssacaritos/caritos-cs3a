import streamlit as st
import importlib.util
from pages import BlockCipher_XOR, Hashing_function, XOR_Cipher, Caesar_Cipher, SecureChatwithDiffieHellman, RSACipher  

st.set_page_config(page_title="Applied Cryptography", page_icon="♨️")

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
    "SecureChatwithDiffieHellman.py": (SecureChatwithDiffieHellman.main, "Secure Chat with Diffie-Hellman", "🔑🔒"),
    "RSACipher.py": (RSACipher.main, "RSA Cipher Exchange", "🔑")
}

# Define algorithm details including description and pseudocode
algorithm_details = {
    "Block Cipher XOR": {
        "Description": "Block Cipher XOR is a symmetric encryption algorithm that encrypts plaintext by performing bitwise XOR operation with a key.",
        "Pseudocode": "1. Divide plaintext into fixed-size blocks.\n2. Apply XOR operation between each block and the key.\n3. Repeat until all blocks are encrypted."
    },
    "XOR Cipher": {
        "Description": "XOR Cipher is a symmetric encryption algorithm that encrypts plaintext by performing bitwise XOR operation with a key.",
        "Pseudocode": "1. Apply XOR operation between plaintext and the key."
    },
    "Caesar Cipher": {
        "Description": "Caesar Cipher is a substitution cipher where each letter in the plaintext is shifted a certain number of places down or up the alphabet.",
        "Pseudocode": "1. Shift each letter in the plaintext by a fixed number of positions."
    },
    "Hashing Function": {
        "Description": "A Hashing Function takes an input (or 'message') and returns a fixed-size string of bytes. The output is typically a hash value.",
        "Pseudocode": "1. Convert input message to a fixed-length hash value."
    },
    "Secure Chat with Diffie-Hellman": {
        "Description": "Secure Chat with Diffie-Hellman is an example of key exchange protocol that allows two parties to establish a shared secret key over an insecure channel.",
        "Pseudocode": "1. Perform key exchange using modular arithmetic."
    },
    "RSA Cipher Exchange": {
        "Description": "RSA Cipher Exchange is an asymmetric encryption algorithm that uses a pair of public and private keys for encryption and decryption.",
        "Pseudocode": "1. Generate public and private keys.\n2. Encrypt plaintext using the recipient's public key.\n3. Decrypt ciphertext using the recipient's private key."
    }
}

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
            Aguilar, Jhan Lenard Troa

        The Applied Cryptography Application project aims to develop a simple application that implements various cryptographic techniques to secure communication, data, and information exchange. Cryptography is the science of encoding and decoding messages to protect their confidentiality, integrity, and authenticity. 

        This application covers the following cryptographic techniques:
        
        - **Symmetric Encryption and Decryption**: In symmetric encryption, the same key is used for both encryption and decryption. It's fast and efficient but requires secure key distribution. Examples include the Block Cipher XOR, XOR Cipher, and Caesar Cipher.

        - **Asymmetric Encryption and Decryption**: Asymmetric encryption uses a pair of keys - public and private keys. The public key is used for encryption, while the private key is used for decryption. It provides secure key exchange but is slower compared to symmetric encryption. An example is the Secure Chat with Diffie-Hellman and RSA Encryption and Decryption.

        - **Hashing Function**: Hashing functions take an input (or 'message') and return a fixed-size string of bytes. The output is typically a hash value. Hash functions are commonly used in various aspects of cryptography, including password storage and digital signatures.
        
        The application will provide a user-friendly interface that allows users to encrypt, decrypt, and hash messages/files using different cryptographic algorithms 🤖.
        """)
else:
    # Display buttons for each .py file in the main content area
    selected_page = st.selectbox("Your Preview Page", page_names)

    # Show content of the selected page
    if selected_page:
        function_to_execute, _, emoji = [values for values in file_functions.values() if values[1] == selected_page][0]
        if function_to_execute:
            st.markdown(f"## {selected_page} {emoji}")
            function_to_execute()
        else:
            st.write("This page does not have an executable function.")
