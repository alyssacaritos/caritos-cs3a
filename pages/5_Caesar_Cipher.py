import streamlit as st
import pandas as pd

st.set_page_config(page_title="Caesar Cipher", page_icon=":lock:", layout="wide")

# Function to encrypt or decrypt text using Caesar Cipher
def encrypt_decrypt(text, shift_keys, if_encrypt):
    """
    Encrypts or decrypts a text using Caesar Cipher with a list of shift keys.
    Args:
        text: The text to encrypt/decrypt.
        shift_keys: A list of integers representing the shift values for each character.
        if_encrypt: Flag to determine if encrypting (True) or decrypting (False).
    Returns:
        A string containing the encrypted text if encrypting or plain text if decrypting.
    """
    
    result = ""
    interchange_values = []
    
    if len(shift_keys) <= 1 or len(shift_keys) > len(text):
        raise ValueError("Invalid shift keys length")
        
    for i, char in enumerate(text):
        shift_key = shift_keys[i % len(shift_keys)]
        original_char = char
        
        if 32 <= ord(char) <= 125:
            if if_encrypt:
                new_ascii = ord(char) + shift_key
            else:
                new_ascii = ord(char) - shift_key
                
            new_ascii = 32 + (new_ascii - 32) % 94
            result_char = chr(new_ascii)
        else:
            result_char = char
        
        result += result_char
        interchange_values.append((original_char, shift_key, result_char))
    
    return result, interchange_values

# Streamlit UI
st.title(":lock: Caesar Cipher")

with st.form("caesar_cipher_form"):
    st.subheader("Encrypt or Decrypt Text")
    
    text = st.text_area("Enter text:")
    shift_keys = st.text_area("Enter shift keys separated by spaces:")
    encrypt_option = st.radio("Choose an option:", ("Encrypt", "Decrypt"))
    
    submitted = st.form_submit_button("Submit")

if submitted:
    if not text.strip() or not shift_keys:
        st.error("Please enter both text and shift keys.")
    else:
        try:
            shift_keys = [int(key) for key in shift_keys.split()]
            if encrypt_option == "Encrypt":
                decrypted_text, interchange_values = encrypt_decrypt(text, shift_keys, False)
                output_df = pd.DataFrame(interchange_values, columns=["Original Character", "Shift Key", "Encrypted Character"])
                st.subheader("Encrypted Text:")
                st.write(decrypted_text)
                st.subheader("Decryption:")
                st.dataframe(output_df)
            else:
                encrypted_text, interchange_values = encrypt_decrypt(text, shift_keys, True)
                output_df = pd.DataFrame(interchange_values, columns=["Original Character", "Shift Key", "Decrypted Character"])
                st.subheader("Decrypted Text:")
                st.write(encrypted_text)
                st.subheader("Decryption:")
                st.dataframe(output_df)
        except ValueError as e:
            st.error("Error: " + str(e))
