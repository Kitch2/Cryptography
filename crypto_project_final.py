import time
import os
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1, OAEP

# Automatically choose the correct backend for interactive environments (like Jupyter or IDEs)
try:
    plt.switch_backend('TkAgg')  # This is for interactive environments
except:
    plt.switch_backend('Agg')   # Use Agg for non-interactive environments (e.g., script mode)

# RSA Keypair Generation
def rsa_keypair_generation(key_size=2048):
    start = time.perf_counter()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    gen_time = time.perf_counter() - start
    return private_key, public_key, gen_time

# DSA Keypair Generation
def dsa_keypair_generation(key_size=1024):
    start = time.perf_counter()
    private_key = dsa.generate_private_key(key_size=key_size)
    public_key = private_key.public_key()
    gen_time = time.perf_counter() - start
    return private_key, public_key, gen_time

# ECC Keypair Generation
def ecc_keypair_generation(curve=ec.SECP256R1()):
    start = time.perf_counter()
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    gen_time = time.perf_counter() - start
    return private_key, public_key, gen_time

# RSA Encryption/Decryption with Chunking
def rsa_encrypt_with_chunking(message, public_key, key_size=2048):
    # Calculate maximum chunk size for encryption
    max_chunk_size = (key_size // 8) - 2 * hashes.SHA256().digest_size - 2
    chunks = [message[i:i + max_chunk_size] for i in range(0, len(message), max_chunk_size)]
    
    ciphertext_chunks = []
    for chunk in chunks:
        ciphertext_chunks.append(
            public_key.encrypt(
                chunk,
                OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
        )
    return ciphertext_chunks

def rsa_decrypt_with_chunking(ciphertext_chunks, private_key):
    decrypted_chunks = []
    for chunk in ciphertext_chunks:
        decrypted_chunks.append(
            private_key.decrypt(
                chunk,
                OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
        )
    return b"".join(decrypted_chunks)

def rsa_encrypt_decrypt(message, public_key, private_key, key_size=2048):
    start = time.perf_counter()
    ciphertext_chunks = rsa_encrypt_with_chunking(message, public_key, key_size)
    decrypted_message = rsa_decrypt_with_chunking(ciphertext_chunks, private_key)
    op_time = time.perf_counter() - start
    return ciphertext_chunks, decrypted_message, op_time

# RSA Signing
def rsa_sign(message, private_key):
    start = time.perf_counter()
    signature = private_key.sign(
        message,
        PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    sign_time = time.perf_counter() - start
    return signature, sign_time

# RSA Verification
def rsa_verify(message, signature, public_key):
    start = time.perf_counter()
    public_key.verify(
        signature,
        message,
        PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    verify_time = time.perf_counter() - start
    return verify_time

# DSA Signing
def dsa_sign(message, private_key):
    start = time.perf_counter()
    signature = private_key.sign(message, hashes.SHA256())
    sign_time = time.perf_counter() - start
    return signature, sign_time

# DSA Verification
def dsa_verify(message, signature, public_key):
    start = time.perf_counter()
    public_key.verify(signature, message, hashes.SHA256())
    verify_time = time.perf_counter() - start
    return verify_time

# ECC Signing
def ecc_sign(message, private_key):
    start = time.perf_counter()
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    sign_time = time.perf_counter() - start
    return signature, sign_time

# ECC Verification
def ecc_verify(message, signature, public_key):
    start = time.perf_counter()
    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    verify_time = time.perf_counter() - start
    return verify_time

# ECC Security Levels
def get_ecc_curve_security(curve):
    curve_mapping = {
        ec.SECP192R1: "80-bit security",
        ec.SECP224R1: "112-bit security",
        ec.SECP256R1: "128-bit security",
        ec.SECP384R1: "192-bit security",
        ec.SECP521R1: "256-bit security"
    }
    return curve_mapping[type(curve)]

# Benchmark Function with Separate Signing and Verification
def benchmark_operations(algorithm, params, message, label, operation):
    print(f"\n{'=' * 40}")
    print(f"{algorithm} {operation.capitalize()} Benchmark")
    print(f"{'=' * 40}")
    print(f"{'Parameter':<20} {'Time (seconds)':>15}")
    print(f"{'-' * 40}")
    results = []
    for param in params:
        if algorithm == "RSA":
            private_key, public_key, _ = rsa_keypair_generation(key_size=param)
            if operation == "keypair":
                _, _ , gen_time = rsa_keypair_generation(key_size=param)
                results.append((f"{param} bits", gen_time))
            elif operation == "encrypt_decrypt":
                ciphertext, decrypted_message, op_time = rsa_encrypt_decrypt(message, public_key, private_key, key_size=param)
                results.append((f"{param} bits", op_time))
            elif operation == "sign":
                signature, sign_time = rsa_sign(message, private_key)
                results.append((f"{param} bits", sign_time))
            elif operation == "verify":
                signature, _ = rsa_sign(message, private_key)
                verify_time = rsa_verify(message, signature, public_key)
                results.append((f"{param} bits", verify_time))
        elif algorithm == "DSA":
            private_key, public_key, _ = dsa_keypair_generation(key_size=param)
            if operation == "keypair":
                _, _, gen_time = dsa_keypair_generation(key_size=param)
                results.append((f"{param} bits", gen_time))
            elif operation == "sign":
                signature, sign_time = dsa_sign(message, private_key)
                results.append((f"{param} bits", sign_time))
            elif operation == "verify":
                signature, _ = dsa_sign(message, private_key)
                verify_time = dsa_verify(message, signature, public_key)
                results.append((f"{param} bits", verify_time))
        elif algorithm == "ECC":
            curve = param
            private_key, public_key, _ = ecc_keypair_generation(curve=curve)
            if operation == "keypair":
                _, _, gen_time = ecc_keypair_generation(curve=curve)
                results.append((get_ecc_curve_security(curve), gen_time))
            elif operation == "sign":
                signature, sign_time = ecc_sign(message, private_key)
                results.append((get_ecc_curve_security(curve), sign_time))
            elif operation == "verify":
                signature, _ = ecc_sign(message, private_key)
                verify_time = ecc_verify(message, signature, public_key)
                results.append((get_ecc_curve_security(curve), verify_time))

        param_label = param if algorithm != "ECC" else get_ecc_curve_security(param)
        print(f"{param_label:<20} {results[-1][1]:>15.4f}")
    return results

# Plot Results
def plot_results(algorithm, results, operation):
    params = [r[0] for r in results]
    times = [r[1] for r in results]

    plt.figure(figsize=(10, 6))
    plt.plot(params, times, label=f"{operation.capitalize()} Time (s)", marker="o")
    plt.title(f"{algorithm} {operation.capitalize()} Benchmark")
    plt.xlabel("Parameter (Key Size or Security Level)")
    plt.ylabel("Time (seconds)")
    plt.legend()
    plt.grid(True)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f"{algorithm.lower()}_{operation}_benchmark.png")
    plt.show()

# Main Script
def main():
    message = os.urandom(10 * 1024)  # 10KB random message

    # Benchmark RSA
    rsa_key_sizes = [1024, 2048, 3072]
    rsa_keypair_results = benchmark_operations("RSA", rsa_key_sizes, message, "RSA Keypair Generation", "keypair")
    rsa_encrypt_results = benchmark_operations("RSA", rsa_key_sizes, message, "RSA Encryption/Decryption", "encrypt_decrypt")
    rsa_sign_results = benchmark_operations("RSA", rsa_key_sizes, message, "RSA Signing", "sign")
    rsa_verify_results = benchmark_operations("RSA", rsa_key_sizes, message, "RSA Verification", "verify")
    plot_results("RSA", rsa_keypair_results, "keypair")
    plot_results("RSA", rsa_encrypt_results, "encrypt_decrypt")
    plot_results("RSA", rsa_sign_results, "sign")
    plot_results("RSA", rsa_verify_results, "verify")

    # Benchmark DSA
    dsa_key_sizes = [1024, 2048]
    dsa_keypair_results = benchmark_operations("DSA", dsa_key_sizes, message, "DSA Keypair Generation", "keypair")
    dsa_sign_results = benchmark_operations("DSA", dsa_key_sizes, message, "DSA Signing", "sign")
    dsa_verify_results = benchmark_operations("DSA", dsa_key_sizes, message, "DSA Verification", "verify")
    plot_results("DSA", dsa_keypair_results, "keypair")
    plot_results("DSA", dsa_sign_results, "sign")
    plot_results("DSA", dsa_verify_results, "verify")

    # Benchmark ECC
    ecc_curves = [ec.SECP192R1(), ec.SECP224R1(), ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]
    ecc_keypair_results = benchmark_operations("ECC", ecc_curves, message, "ECC Keypair Generation", "keypair")
    ecc_sign_results = benchmark_operations("ECC", ecc_curves, message, "ECC Signing", "sign")
    ecc_verify_results = benchmark_operations("ECC", ecc_curves, message, "ECC Verification", "verify")
    plot_results("ECC", ecc_keypair_results, "keypair")
    plot_results("ECC", ecc_sign_results, "sign")
    plot_results("ECC", ecc_verify_results, "verify")

if __name__ == "__main__":
    main()