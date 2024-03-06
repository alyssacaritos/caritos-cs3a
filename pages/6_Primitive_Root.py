import streamlit as st

st.header("Primitive Root")

def is_prime(q):
    if q < 2:
        return False
    i = 2
    while i*i <= q:
        if q % i == 0:
            return False
        i += 1
    return True

def get_primitive(q):
    primitive_roots = []
    for g in range(1, q):
        is_primitive_root = True
        powers = set()
        for j in range(1, q):
            res = compute_modulo(g, j, q)
            powers.add(res)
            if res == 1:
                break
        if len(powers) == q - 1:
            primitive_roots.append(g)
    return primitive_roots

def compute_modulo(base, exponent, mod):
    result = 1
    for _ in range(exponent):
        result = (result * base) % mod
    return result

def print_results(q, g):
    if not is_prime(q):
        st.write(f"{q} is not a prime number!!")
        return
    
    primitive_roots = get_primitive(q)
    results_table = "| g | Powers mod q | Result |\n|---|--------------|--------|"
    for g_value in range(1, q):
        powers = []
        for j in range(1, q):
            res = compute_modulo(g_value, j, q)
            powers.append(res)
            if res == 1:
                break
        result_str = ', '.join([f"{g_value}^{j} mod {q} = {res}" for j, res in enumerate(powers, 1)])
        is_primitive = f"Primitive Root of {q}" if g_value in primitive_roots else ""
        results_table += f"\n| {g_value} | {result_str} | {is_primitive} |"

    st.markdown(results_table)

    if g in primitive_roots:
        st.write(f"{g} is a primitive root: True", primitive_roots)
    else:
        st.write(f"{g} is NOT a primitive root of {q} - List of Primitive roots:", primitive_roots)

q_input = st.text_input("Enter Prime Number:")
g_input = st.text_input("Enter Primitive Root:")

if st.button("Submit"):
    if not q_input or not g_input:
        st.error("Please enter both the prime number and the primitive root.")
    else:
        try:
            q = int(q_input)
            g = int(g_input)
            print_results(q, g)
        except ValueError:
            st.error("Please enter valid numeric values for both the prime number and the primitive root.")
