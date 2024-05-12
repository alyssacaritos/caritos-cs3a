import streamlit as st

st.title("🔐 Secure Chat using Diffie-Hellman Key Exchange 🔐")

def is_prime(q):
    if q < 2:
        return False
    i = 2
    while i * i <= q:
        if q % i == 0:
            return False
        i += 1
    return True

def compute_modulo(base, exponent, mod):
    result = 1
    for _ in range(exponent):
        result = (result * base) % mod
    return result

def xor_encrypt_decrypt(message, key):
    encrypted = ''.join(chr(ord(m) ^ key) for m in message)
    return encrypted

def generate_keys(q, g, private_key):
    public_key = compute_modulo(g, private_key, q)
    return public_key

def compute_shared_secret(public_key, private_key, q):
    return compute_modulo(public_key, private_key, q)

def secure_chat(private_key, received_public_key, message):
    shared_secret = compute_shared_secret(received_public_key, private_key, q)
    encrypted_message = xor_encrypt_decrypt(message, shared_secret)
    return encrypted_message


q = st.sidebar.number_input("#️⃣Enter Prime Number (q):", min_value=2, step=1)
g = st.sidebar.number_input("#️⃣Enter Primitive Root (g):", min_value=2, step=1)
private_key = st.sidebar.number_input("#️⃣Enter Your Private Key:", min_value=5, step=1)

st.sidebar.markdown("### 🛡️ Your Public Key 🛡️")
received_public_key = st.sidebar.number_input("Enter Received Public Key:", min_value=1, step=1)

st.markdown("### 📧 CHAT 📧", unsafe_allow_html=True)

message = st.text_area("Type Your Message:")

if st.button("Send"):
    if not is_prime(q):
        st.error("Please enter a valid prime number for 'q'.")
    else:
        try:
            your_public_key = generate_keys(q, g, private_key)
            encrypted_message = secure_chat(private_key, received_public_key, message)
            st.write(f"🔒 Your Sent Message: {encrypted_message}")
            
        except Exception as e:
            st.error(f"An error occurred: {str(e)}")

received_message = st.text_input("Enter Received Message:")

if st.button("Receive"):
    try:
        decrypted_message = secure_chat(private_key, received_public_key, received_message)
        st.write(f"🔓 Received Message: {decrypted_message}")
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")

st.sidebar.write(f"Your Public Key: {generate_keys(q, g, private_key)}")

def main():
    secure_chat(private_key, received_public_key, message)

if __name__ == "__main__":
    main()

