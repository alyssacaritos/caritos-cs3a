import streamlit as st

st.set_page_config(page_title="Block Cipher - XOR", layout="wide")

st.title("Block Cipher - XOR")

def pad(data, block_size):
    padding_length = block_size - len(data) % block_size  
    padding = bytes([padding_length] * padding_length)  
    return data + padding                         

def unpad(data):
    padding_length = data[-1]                                
    return data[:-padding_length]                           

def xor_encrypt_block(plaintext_block, key):
    encrypted_block = b''
    for i in range(len(plaintext_block)):
        encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
    return encrypted_block                  

def xor_decrypt_block(ciphertext_block, key):
    return xor_encrypt_block(ciphertext_block, key)  

def xor_encrypt(plaintext, key, block_size):
    encrypted_data = b''
    padded_plaintext = pad(plaintext, block_size)
    
    st.markdown("### Encrypted Blocks", unsafe_allow_html=True)
    for x, i in enumerate(range(0, len(padded_plaintext), block_size)):
        plaintext_block = padded_plaintext[i:i+block_size]
        st.markdown(f"#### Plain block[{x}]:", unsafe_allow_html=True)
        st.markdown(f"<b>Hex:</b> {plaintext_block.hex()}", unsafe_allow_html=True)
        st.markdown(f"<b>Text:</b> {plaintext_block}", unsafe_allow_html=True)

        encrypted_block = xor_encrypt_block(plaintext_block, key)
        st.markdown(f"#### Cipher block[{x}]:", unsafe_allow_html=True)
        st.markdown(f"<b>Hex:</b> {encrypted_block.hex()}", unsafe_allow_html=True)
        st.markdown(f"<b>Text:</b> {encrypted_block}", unsafe_allow_html=True)
        
        encrypted_data += encrypted_block

    return encrypted_data                              

def xor_decrypt(ciphertext, key, block_size):
    decrypted_data = b''
    
    st.markdown("### Decrypted Blocks", unsafe_allow_html=True)
    for x, i in enumerate(range(0, len(ciphertext), block_size)):
        ciphertext_block = ciphertext[i:i+block_size]
        
        decrypted_block = xor_decrypt_block(ciphertext_block, key)
        
        st.markdown(f"#### Block[{x}]:", unsafe_allow_html=True)
        st.markdown(f"<b>Hex:</b> {decrypted_block.hex()}", unsafe_allow_html=True)
        st.markdown(f"<b>Text:</b> {decrypted_block}", unsafe_allow_html=True)
        
        decrypted_data += decrypted_block

    unpadded_decrypted_data = unpad(decrypted_data)
    
    return unpadded_decrypted_data                              

if __name__ == "__main__":
    plaintext_input = st.text_area("Plain Text:")
    key_input = st.text_input("Key:")
    block_size_input = st.text_input("Block Size:")
    submit_button = st.button("Submit")
    
    if submit_button:
        if not plaintext_input.strip() or not key_input.strip() or not block_size_input.strip():
            st.error("Please fill in all the fields.")
        else:
            plaintext = bytes(plaintext_input.encode())
            key = bytes(key_input.encode())
            try:
                block_size = int(block_size_input)
                if block_size not in [8, 16, 32, 64, 128]:
                    st.write('Block size must be one of 8, 16,  32, 64, or  128 bytes')
                else:
                    key = pad(key, block_size)
                    encrypted_data = xor_encrypt(plaintext, key, block_size)
                    decrypted_data = xor_decrypt(encrypted_data, key, block_size)
                    st.markdown("#### Original plaintext:", unsafe_allow_html=True)
                    st.code(plaintext)
                    st.markdown("#### Key byte:", unsafe_allow_html=True)
                    st.code(key)
                    st.markdown("#### Key hex:", unsafe_allow_html=True)
                    st.code(key.hex())
                    st.markdown("#### Encrypted data:", unsafe_allow_html=True)
                    st.code(encrypted_data.hex())
                    st.markdown("#### Decrypted data:", unsafe_allow_html=True)
                    st.code(decrypted_data.hex())
                    st.markdown("#### Decrypted data:", unsafe_allow_html=True)
                    st.code(decrypted_data)
            except ValueError:
                st.error("Please enter a valid integer for block size.")
