import streamlit as st

st.header("Caesar Cipher")

def encrypt_decrypt(text, shift_keys, ifdecrypt):
    """
    Encrypts or decrypts a text using Caesar Cipher with a list of shift keys.
    Args:
        text: The text to encrypt/decrypt.
        shift_keys: A list of integers representing the shift values for each character.
        ifdecrypt: Flag to determine if decrypting (True) or encrypting (False).
    Returns:
        A string containing the encrypted text if encrypting or plain text if decrypting.
    """
    
    result = ""
    
    if len(shift_keys) <= 1 or len(shift_keys) > len(text):
        raise ValueError("Invalid shift keys length")
        
    for i, char in enumerate(text):
        shift_key = shift_keys[i % len(shift_keys)]
        
        if 32 <= ord(char) <= 125:
            
            if not ifdecrypt:
                new_ascii = ord(char) + shift_key
            else:
                new_ascii = ord(char) - shift_key
                
            new_ascii = 32 + (new_ascii - 32) % 94
                
            result += chr(new_ascii)
        else:
            result += char
        st.write(i, char, shift_key, result[i])
    return result

text = st.text_area("Enter text:")
shift_keys = st.text_area("Enter shift keys separated by spaces:").split()
shift_keys = [int(key) for key in shift_keys]

if st.button("Submit"):
    if not text.strip() or not shift_keys:
        st.error("Please enter both text and shift keys.")
    else:
        try:
            def Output(text, shift_keys, enc, dec):
                st.write("Text:", text)
                st.write("Shift Keys:", *shift_keys)
                st.write("Cipher:", enc)
                st.write("Decrypted Text:", dec)

            enc = encrypt_decrypt(text, shift_keys, False)
            st.write("----------")
            dec = encrypt_decrypt(enc, shift_keys, True)
            st.write("----------")

            Output(text, shift_keys, enc, dec)
        except ValueError as e:
            st.error("Error: " + str(e))
