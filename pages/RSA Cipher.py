import streamlit as st
import math

def is_prime(num):
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keys(p, q):
    if not is_prime(p) or not is_prime(q):
        st.error("Both numbers must be prime.")
        return None, None, None, None, None, None

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 2
    while gcd(e, phi) != 1:
        e += 1

    d = mod_inverse(e, phi)

    return (e, n), (d, n), phi, n, p, q

def encrypt(message, public_key):
    e, n = public_key
    encrypted_text = [pow(ord(char), e, n) for char in message]
    return encrypted_text

def decrypt(encrypted_text, private_key):
    d, n = private_key
    decrypted_text = [chr(pow(char, d, n)) for char in encrypted_text]
    return ''.join(decrypted_text)

if __name__ == '__main__':
    st.title("RSA Chat")

    public_key = None
    private_key = None

    st.sidebar.header("RSA Key Generation")
    p = st.sidebar.number_input("Enter the first prime number (p):", min_value=2, step=1)
    q = st.sidebar.number_input("Enter the second prime number (q):", min_value=2, step=1)

    if st.sidebar.button("Generate Keys"):
        public_key, private_key, phi, n, p, q = generate_keys(p, q)

        if public_key is not None and private_key is not None:  # Check if keys were successfully generated
            st.sidebar.success("Keys generated successfully.")
            st.sidebar.write(f"p: {p}")
            st.sidebar.write(f"q: {q}")
            st.sidebar.write(f"n: {n}")
            st.sidebar.write(f"φ(n): {phi}")
            st.sidebar.write(f"e: {public_key[0]}")
            st.sidebar.write(f"d: {private_key[0]}")
        else:
            st.sidebar.error("Failed to generate keys. Please ensure both numbers are prime.")

    if public_key is not None and private_key is not None:  # Check if keys exist before using them
        message = st.text_input("Enter your message:")
        if st.button("Encrypt"):
            if message and public_key is not None:  # Ensure public key exists before encryption
                encrypted_message = encrypt(message, public_key)
                encrypted_str = ' '.join(str(p) for p in encrypted_message)
                st.write("Encrypted message:")
                st.write(encrypted_str)
            elif not message:
                st.write("Please enter a message.")
            else:
                st.error("Public key not generated.")

        received_message = st.text_input("Paste the received message here:")
        if st.button("Decrypt"):
            if received_message and private_key is not None:  # Ensure private key exists before decryption
                encrypted_message = [int(num) for num in received_message.split() if num.isdigit()]
                decrypted_message = decrypt(encrypted_message, private_key)
                st.write("Decrypted message:")
                st.write(decrypted_message)
            elif not received_message:
                st.write("Please paste the received message.")
            else:
                st.error("Private key not generated.")
