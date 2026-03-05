"""
RSA Encryption & Decryption — Implementasi From Scratch
Tanpa library enkripsi eksternal. Hanya menggunakan matematika dasar.

Nama   : Wildandy Dwi Ananda
NIM    : 24051204158
Tugas  : Kriptografi — Algoritma RSA
"""

import math
import random

# ─────────────────────────────────────────────────────────────
# STEP 1: Fungsi Pembantu (Helper Functions)
# ─────────────────────────────────────────────────────────────

def is_prime(n):
    """Cek apakah bilangan n adalah bilangan prima."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True

def gcd(a, b):
    """Algoritma Euclidean untuk mencari GCD (Greatest Common Divisor)."""
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Extended Euclidean Algorithm — mencari x, y sehingga ax + by = gcd(a,b)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def mod_inverse(e, phi):
    """Mencari modular inverse d sehingga (e * d) mod phi = 1."""
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("Modular inverse tidak ada (e dan phi tidak coprime).")
    return x % phi

def mod_pow(base, exp, mod):
    """Fast modular exponentiation — menghitung (base^exp) mod mod secara efisien."""
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:          # jika exp ganjil
            result = (result * base) % mod
        exp = exp // 2
        base = (base * base) % mod
    return result

# ─────────────────────────────────────────────────────────────
# STEP 2: Key Generation (Pembangkitan Kunci)
# ─────────────────────────────────────────────────────────────

def generate_keys(p, q):
    """
    Membangkitkan kunci publik (e, n) dan kunci privat (d, n) dari dua bilangan prima p dan q.
    """
    print("=" * 60)
    print("  STEP 2: KEY GENERATION (Pembangkitan Kunci)")
    print("=" * 60)

    # Validasi
    assert is_prime(p), f"{p} bukan bilangan prima!"
    assert is_prime(q), f"{q} bukan bilangan prima!"
    assert p != q, "p dan q harus berbeda!"

    print(f"  Bilangan prima p = {p}")
    print(f"  Bilangan prima q = {q}")

    # Hitung n = p * q
    n = p * q
    print(f"\n  n = p x q = {p} x {q} = {n}")

    # Hitung phi(n) = (p-1)(q-1)
    phi = (p - 1) * (q - 1)
    print(f"  phi(n) = (p-1)(q-1) = ({p}-1)({q}-1) = {phi}")

    # Pilih e: 1 < e < phi, gcd(e, phi) = 1
    e = 65537  # Nilai e standar industri (bilangan prima Fermat ke-5)
    if e >= phi or gcd(e, phi) != 1:
        # Cari e kecil jika phi terlalu kecil
        e = 3
        while e < phi and gcd(e, phi) != 1:
            e += 2

    print(f"\n  Kunci publik e = {e}")
    print(f"  Verifikasi: gcd({e}, {phi}) = {gcd(e, phi)}  (harus = 1)")

    # Hitung d = modular inverse dari e terhadap phi
    d = mod_inverse(e, phi)
    print(f"\n  Kunci privat d = {d}")
    print(f"  Verifikasi: (e x d) mod phi = ({e} x {d}) mod {phi} = {(e * d) % phi}  (harus = 1)")

    print(f"\n  Kunci Publik  : (e={e}, n={n})")
    print(f"  Kunci Privat  : (d={d}, n={n})")
    print()

    return (e, n), (d, n)


# ─────────────────────────────────────────────────────────────
# STEP 3: Enkripsi
# ─────────────────────────────────────────────────────────────

def encrypt(plaintext_int, public_key):
    """
    Enkripsi: C = M^e mod n
    plaintext_int : pesan dalam bentuk integer
    public_key    : tuple (e, n)
    """
    e, n = public_key
    print("=" * 60)
    print("  STEP 3: ENKRIPSI")
    print("=" * 60)
    print(f"  Plaintext (M)   = {plaintext_int}")
    print(f"  Kunci publik e  = {e}")
    print(f"  Modulus n       = {n}")
    print(f"\n  Rumus: C = M^e mod n")
    print(f"         C = {plaintext_int}^{e} mod {n}")
    ciphertext = mod_pow(plaintext_int, e, n)
    print(f"         C = {ciphertext}")
    print(f"\n  Ciphertext      = {ciphertext}")
    print()
    return ciphertext


# ─────────────────────────────────────────────────────────────
# STEP 4: Dekripsi
# ─────────────────────────────────────────────────────────────

def decrypt(ciphertext, private_key):
    """
    Dekripsi: M = C^d mod n
    ciphertext  : pesan terenkripsi (integer)
    private_key : tuple (d, n)
    """
    d, n = private_key
    print("=" * 60)
    print("  STEP 4: DEKRIPSI")
    print("=" * 60)
    print(f"  Ciphertext (C)  = {ciphertext}")
    print(f"  Kunci privat d  = {d}")
    print(f"  Modulus n       = {n}")
    print(f"\n  Rumus: M = C^d mod n")
    print(f"         M = {ciphertext}^{d} mod {n}")
    plaintext = mod_pow(ciphertext, d, n)
    print(f"         M = {plaintext}")
    print(f"\n  Plaintext hasil dekripsi = {plaintext}")
    print()
    return plaintext


# ─────────────────────────────────────────────────────────────
# STEP 5: Enkripsi / Dekripsi String
# ─────────────────────────────────────────────────────────────

def encrypt_string(text, public_key):
    """Enkripsi setiap karakter dalam string menggunakan nilai ASCII-nya."""
    return [mod_pow(ord(ch), public_key[0], public_key[1]) for ch in text]

def decrypt_string(cipher_list, private_key):
    """Dekripsi list ciphertext kembali menjadi string."""
    return "".join(chr(mod_pow(c, private_key[0], private_key[1])) for c in cipher_list)


# ─────────────────────────────────────────────────────────────
# MAIN — Demonstrasi Lengkap
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":

    print("\n" + "=" * 60)
    print("   RSA ENCRYPTION — IMPLEMENTASI FROM SCRATCH")
    print("   Wildandy Dwi Ananda | 24051204158")
    print("=" * 60 + "\n")

    # ── Demo 1: Input bilangan prima dari user ────────────────────
    print("─" * 60)
    print("  DEMO 1: Enkripsi dengan Bilangan Prima Pilihan Anda")
    print("─" * 60 + "\n")

    # Input p
    while True:
        try:
            p = int(input("  Masukkan bilangan prima p : "))
            if is_prime(p):
                break
            else:
                print(f"  X {p} bukan bilangan prima. Coba lagi.\n")
        except ValueError:
            print("  X Input tidak valid. Masukkan bilangan bulat.\n")

    # Input q
    while True:
        try:
            q = int(input("  Masukkan bilangan prima q : "))
            if not is_prime(q):
                print(f"  X {q} bukan bilangan prima. Coba lagi.\n")
            elif q == p:
                print("  X q harus berbeda dari p. Coba lagi.\n")
            else:
                break
        except ValueError:
            print("  X Input tidak valid. Masukkan bilangan bulat.\n")

    print()
    pub, priv = generate_keys(p, q)

    M = 65          # Plaintext: angka 65 (ASCII huruf 'A')
    print(f"  Plaintext yang akan dienkripsi: M = {M}  (karakter ASCII: '{chr(M)}')\n")

    C = encrypt(M, pub)
    M_dec = decrypt(C, priv)

    print("─" * 60)
    print(f"  HASIL AKHIR DEMO 1")
    print(f"  Plaintext asli        : {M}  ('{chr(M)}')")
    print(f"  Ciphertext            : {C}")
    print(f"  Plaintext didekripsi  : {M_dec}  ('{chr(M_dec)}')")
    print(f"  Berhasil? {'YA' if M == M_dec else 'TIDAK'}")
    print("─" * 60 + "\n")

    # ── Demo 2: Enkripsi string (bilangan prima lebih besar) ─────
    print("─" * 60)
    print("  DEMO 2: Enkripsi String Lengkap")
    print("─" * 60 + "\n")

    p2, q2 = 499, 547
    pub2, priv2 = generate_keys(p2, q2)

    pesan = "HELLO RSA"
    print(f"  Pesan asli: \"{pesan}\"\n")

    print("  [Enkripsi karakter per karakter]")
    cipher_list = encrypt_string(pesan, pub2)
    print(f"  Ciphertext (list) : {cipher_list}\n")

    print("  [Dekripsi kembali]")
    hasil = decrypt_string(cipher_list, priv2)
    print(f"  Hasil dekripsi    : \"{hasil}\"")

    print()
    print("─" * 60)
    print(f"  HASIL AKHIR DEMO 2")
    print(f"  Plaintext asli  : \"{pesan}\"")
    print(f"  Hasil dekripsi  : \"{hasil}\"")
    print(f"  Berhasil? {'YA' if pesan == hasil else 'TIDAK'}")
    print("─" * 60 + "\n")

    print("=" * 60)
    print("  SELESAI — Semua proses RSA berjalan dengan benar.")
    print("=" * 60 + "\n")
