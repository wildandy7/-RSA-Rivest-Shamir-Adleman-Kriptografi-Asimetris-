# -RSA-Rivest-Shamir-Adleman-Kriptografi-Asimetris-
# RSA (Rivest–Shamir–Adleman) — Implementasi From Scratch

> Tugas Mata Kuliah Keamanan Informasi  
> Wildandy Dwi Ananda | 24051204158 | S1 Teknik Informatika — UNESA

---

## Deskripsi

Implementasi algoritma enkripsi **RSA** menggunakan Python **tanpa library kriptografi eksternal**. Semua logika matematis — mulai dari pengecekan bilangan prima, GCD, modular inverse, hingga fast modular exponentiation — diimplementasikan dari nol.

Program mendemonstrasikan tiga proses utama RSA:
1. **Key Generation** — pembangkitan kunci publik dan privat
2. **Enkripsi** — mengubah plaintext menjadi ciphertext
3. **Dekripsi** — mengembalikan ciphertext ke plaintext

---

## Struktur File

```
├── rsa_scratch.py   # Implementasi utama RSA from scratch
└── README.md        # Dokumentasi ini
```

---

## Cara Menjalankan

### Prasyarat
- Python 3.x (tidak butuh library tambahan)

### Langkah

```bash
# 1. Clone repositori
git clone https://github.com/username/rsa-from-scratch.git
cd rsa-from-scratch

# 2. Jalankan program
python rsa_scratch.py
```

### Contoh Input & Output

```
============================================================
   RSA ENCRYPTION — IMPLEMENTASI FROM SCRATCH
   Wildandy Dwi Ananda | 24051204158
============================================================

  Masukkan bilangan prima p : 61
  Masukkan bilangan prima q : 53

  n = p x q = 61 x 53 = 3233
  phi(n) = (p-1)(q-1) = 3120

  Kunci Publik  : (e=7, n=3233)
  Kunci Privat  : (d=1783, n=3233)

  C = 65^7 mod 3233 = 1317       ← enkripsi huruf 'A'
  M = 1317^1783 mod 3233 = 65    ← dekripsi kembali ✓
```

> **Catatan:** Program akan menolak input yang bukan bilangan prima secara otomatis.

---

## Fungsi-Fungsi Utama

| Fungsi | Keterangan |
|---|---|
| `is_prime(n)` | Mengecek apakah n adalah bilangan prima |
| `gcd(a, b)` | Mencari GCD menggunakan algoritma Euclidean |
| `mod_inverse(e, phi)` | Extended GCD untuk mencari kunci privat d |
| `mod_pow(base, exp, mod)` | Fast modular exponentiation |
| `generate_keys(p, q)` | Membangkitkan kunci publik dan privat |
| `encrypt(M, public_key)` | Enkripsi: C = M^e mod n |
| `decrypt(C, private_key)` | Dekripsi: M = C^d mod n |

---

## Rumus Inti RSA

| Proses | Rumus |
|---|---|
| Key Generation | n = p × q,  φ(n) = (p−1)(q−1),  d = e⁻¹ mod φ(n) |
| Enkripsi | C = M^e mod n |
| Dekripsi | M = C^d mod n |

---

## Lisensi

Proyek ini dibuat untuk keperluan tugas akademik.
