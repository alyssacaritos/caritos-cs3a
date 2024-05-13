import streamlit as st

# Title of the Streamlit app
st.title("🔐 Secure Chat using Diffie-Hellman Key Exchange 🔐")

# Function to check if a number is prime
def is_prime(q):
    if q < 2:
        return False
    i = 2
    while i * i <= q:
        if q % i == 0:
            return False
        i += 1
    return True

# Function to compute modular exponentiation
def compute_modulo(base, exponent, mod):
    """
    Computes modular exponentiation of a number.
    
    Args:
        base (int): The base number.
        exponent (int): The exponent.
        mod (int): The modulus.

    Returns:
        int: The result of modular exponentiation.
    """
    result = 1
    for _ in range(exponent):
        result = (result * base) % mod
    return result

# Function for XOR encryption and decryption
def xor_encrypt_decrypt(message, key):
    """
    Encrypts or decrypts a message using XOR operation with a key.
    
    Args:
        message (str): The message to encrypt or decrypt.
        key (int): The key for encryption or decryption.

    Returns:
        str: The encrypted or decrypted message.
    """
    encrypted = ''.join(chr(ord(m) ^ key) for m in message)
    return encrypted

# Function to generate public key
def generate_keys(q, g, private_key):
    """
    Generates public key using Diffie-Hellman key exchange algorithm.
    
    Args:
        q (int): Prime number.
        g (int): Primitive root.
        private_key (int): Private key.

    Returns:
        int: The generated public key.
    """
    public_key = compute_modulo(g, private_key, q)
    return public_key

# Function to compute shared secret
def compute_shared_secret(public_key, private_key, q):
    """
    Computes shared secret using received public key and own private key.
    
    Args:
        public_key (int): Received public key.
        private_key (int): Own private key.
        q (int): Prime number.

    Returns:
        int: The computed shared secret.
    """
    return compute_modulo(public_key, private_key, q)

# Function for secure chat
def secure_chat(private_key, received_public_key, message):
    """
    Implements secure chat using Diffie-Hellman key exchange and XOR encryption.
    
    Args:
        private_key (int): Own private key.
        received_public_key (int): Received public key.
        message (str): Message to be sent or received.

    Returns:
        str: The encrypted or decrypted message.
    """
    shared_secret = compute_shared_secret(received_public_key, private_key, q)
    encrypted_message = xor_encrypt_decrypt(message, shared_secret)
    return encrypted_message

# Input parameters for Diffie-Hellman key exchange
q = st.sidebar.number_input("#️⃣Enter Prime Number (q):", min_value=2, step=1)
g = st.sidebar.number_input("#️⃣Enter Primitive Root (g):", min_value=2, step=1)
private_key = st.sidebar.number_input("#️⃣Enter Your Private Key:", min_value=5, step=1)

# Input for received public key
st.sidebar.markdown("### 🛡️ Your Public Key 🛡️")
received_public_key = st.sidebar.number_input("Enter Received Public Key:", min_value=1, step=1)

# Chat interface
st.markdown("### 📧 CHAT 📧", unsafe_allow_html=True)

# Input field for message
message = st.text_area("Type Your Message:")

# Button to send message
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

# Input field for received message
received_message = st.text_input("Enter Received Message:")

# Button to receive message
if st.button("Receive"):
    try:
        decrypted_message = secure_chat(private_key, received_public_key, received_message)
        st.write(f"🔓 Received Message: {decrypted_message}")
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")

# Display user's public key
st.sidebar.write(f"Your Public Key: {generate_keys(q, g, private_key)}")

def main():
    secure_chat(private_key, received_public_key, message)

if __name__ == "__main__":
    main()
