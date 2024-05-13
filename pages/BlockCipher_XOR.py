import streamlit as st

st.title("🔒 Block Cipher - XOR 🔑")

def pad(data, block_size):
    """
    Pads the given data to ensure its length is a multiple of the block size.

    Args:
        data (bytes): The data to be padded.
        block_size (int): The block size.

    Returns:
        bytes: The padded data.
    """
    padding_length = block_size - len(data) % block_size  
    padding = bytes([padding_length] * padding_length)  
    return data + padding                         

def unpad(data):
    """
    Removes padding from the given data.

    Args:
        data (bytes): The padded data.

    Returns:
        bytes: The unpadded data.
    """
    padding_length = data[-1]                                
    return data[:-padding_length]                           

def xor_encrypt_block(plaintext_block, key):
    """
    Encrypts a plaintext block using XOR cipher with the given key.

    Args:
        plaintext_block (bytes): The plaintext block to be encrypted.
        key (bytes): The encryption key.

    Returns:
        bytes: The encrypted block.
    """
    encrypted_block = b''
    for i in range(len(plaintext_block)):
        encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
    return encrypted_block                  

def xor_decrypt_block(ciphertext_block, key):
    """
    Decrypts a ciphertext block using XOR cipher with the given key.

    Args:
        ciphertext_block (bytes): The ciphertext block to be decrypted.
        key (bytes): The decryption key.

    Returns:
        bytes: The decrypted block.
    """
    return xor_encrypt_block(ciphertext_block, key)  

def xor_encrypt(plaintext, key, block_size):
    """
    Encrypts plaintext using XOR cipher with the given key and block size.

    Args:
        plaintext (bytes): The plaintext to be encrypted.
        key (bytes): The encryption key.
        block_size (int): The block size.

    Returns:
        bytes: The encrypted data.
    """
    encrypted_data = b''
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]
        padded_block = pad(block, block_size)
        encrypted_block = xor_encrypt_block(padded_block, key)
        encrypted_data += encrypted_block
    return encrypted_data

def xor_decrypt(ciphertext, key, block_size):
    """
    Decrypts ciphertext using XOR cipher with the given key and block size.

    Args:
        ciphertext (bytes): The ciphertext to be decrypted.
        key (bytes): The decryption key.
        block_size (int): The block size.

    Returns:
        bytes: The decrypted data.
    """
    decrypted_data = b''
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        decrypted_block = xor_decrypt_block(block, key)
        # Since we're padding the plaintext, we need to consider the padding length
        # when appending blocks to the decrypted data
        decrypted_data += decrypted_block
    return unpad(decrypted_data)

def block_cipher_xor():
    """
    Streamlit app for encrypting and decrypting using XOR block cipher.
    """
    st.sidebar.title("📥 Choose Input Option")
    input_option = st.sidebar.radio("Choose Input Option", ("📝 Text", "📂 File"), key="input_option")
    if input_option == "📝 Text":
        plaintext_input = st.text_area("📜 Input Text:")
        block_size_input = st.selectbox("🔢 Block Size:", (8, 16, 32, 64, 128))
        key_input = st.text_input("🔑 Input Key:")
    else:
        uploaded_file = st.file_uploader("📤 Upload File:")
        if uploaded_file is not None:
            plaintext_input = uploaded_file.read()
            block_size_input = st.selectbox("🔢 Block Size:", (8, 16, 32, 64, 128))
            key_input = st.text_input("🔑 Input Key:")
    
    show_steps_encrypt = st.checkbox("🔒 Show Encryption Steps")
    show_steps_decrypt = st.checkbox("🔓 Show Decryption Steps")
    
    submit_button = st.button("🔐 Encrypt & Decrypt")
    if submit_button:
        if not plaintext_input.strip() or not key_input.strip():
            st.error("Please fill in all the fields.")
        else:
            key = bytes(key_input, "utf-8")
            block_size = int(block_size_input)
            
            if input_option == "📂 File":
                plaintext = plaintext_input
            else:
                plaintext = bytes(plaintext_input, "utf-8")
                
            encrypted_data = xor_encrypt(plaintext, key, block_size)
            decrypted_data = xor_decrypt(encrypted_data, key, block_size)
            
            st.markdown("### 🔐 Encrypted Data", unsafe_allow_html=True)
            st.code(encrypted_data.hex())
    
            
            st.markdown("### 🔓 Decrypted Data", unsafe_allow_html=True)
            try:
                decrypted_text = decrypted_data.decode('utf-8')
                st.code(decrypted_text)
            except UnicodeDecodeError:
                st.code(decrypted_data.hex())

            
            if show_steps_encrypt or show_steps_decrypt:
                col1, col2 = st.columns(2)
                
                if show_steps_encrypt:
                    with col1:
                        st.markdown("### 🔒 Encryption Steps", unsafe_allow_html=True)
                        for i in range(0, len(plaintext), block_size):
                            block = plaintext[i:i+block_size]
                            padded_block = pad(block, block_size)
                            encrypted_block = xor_encrypt_block(padded_block, key)
                            st.markdown(f"Block {i//block_size + 1}: ")
                            st.markdown(f"Encrypted: `{encrypted_block.hex()}`")
                
                if show_steps_decrypt:
                    with col2:
                        st.markdown("### 🔓 Decryption Steps", unsafe_allow_html=True)
                        for i in range(0, len(encrypted_data), block_size):
                            block = encrypted_data[i:i+block_size]
                            decrypted_block = xor_decrypt_block(block, key)
                            st.markdown(f"Block {i//block_size + 1}: ")
                            st.markdown(f"Ciphertext: `{block.hex()}`")
                            st.markdown(f"Decrypted: `{decrypted_block.decode()}`")


pass

if __name__ == "__main__":
    #Execute THE PROGRAM
    block_cipher_xor() 
