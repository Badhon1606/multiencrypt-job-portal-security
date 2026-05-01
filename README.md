# MultiEncrypt Job Portal Security

> A job portal application secured by a pure-PHP hybrid encryption scheme — RSA-2048 (OAEP) + ECC secp256k1 (ECIES) + HMAC-SHA256 — implementing field-level encryption for all user PII. Built without any external cryptographic libraries.

---

## What This Is

MultiEncrypt Job Portal Security is a job portal application secured by a cryptographic engine written entirely in PHP using the GMP extension for arbitrary-precision arithmetic. It implements:

- **RSA-2048** with OAEP padding from scratch
- **Elliptic Curve Cryptography** on the secp256k1 curve (the same curve used in Bitcoin)
- **ECIES** (Elliptic Curve Integrated Encryption Scheme) — asymmetric encryption built on top of ECC
- **SHA-256** — custom implementation used as a stream cipher in counter mode
- **HMAC-SHA256** — for ciphertext integrity and authentication
- **MultiEncrypt** — a hybrid scheme that composes all of the above for field-level database encryption

Every sensitive user field (name, email, address, phone, etc.) is independently encrypted at rest using the custom `MultiEncrypt` engine.

---

## Encryption Scheme

Each field is encrypted through a 5-layer hybrid pipeline:

```
Plaintext
    │
    ▼
① Generate random 32-byte data key K (per field, per write)
    │
    ▼
② Encrypt plaintext with SHA256 counter-mode stream cipher
   (nonce ⊕ SHA256(K ‖ counter) XOR stream)
    │
    ▼
③ Wrap K with RSA-2048 OAEP
   (label = "fieldkey:v{version}" binds key to field and version)
    │
    ▼
④ Wrap RSA ciphertext with ECIES (secp256k1)
   (ephemeral ECDH → shared secret → AES-style stream over RSA blob)
    │
    ▼
⑤ Compute HMAC-SHA256 over AAD = userId | fieldName | keyVersion
   (integrity + binds ciphertext to its context, prevents swapping)
    │
    ▼
Base64-encoded JSON blob  →  stored in database column
{v, alg, nonce, cipher, wrapped_key, mac, aad}
```

**Algorithm tag stored in every blob:** `RSA-OAEP+ECIES+HMAC-SHA256`

---

## Cryptographic Modules

| File | Description |
|---|---|
| `crypto/MultiEncrypt.php` | Entry point — orchestrates the full encrypt/decrypt pipeline |
| `crypto/RSA.php` | RSA-2048 key generation, OAEP encrypt/decrypt (GMP-based) |
| `crypto/ECC.php` | Elliptic curve point arithmetic on secp256k1 |
| `crypto/ECIES.php` | Hybrid ECC encryption — ECDH key agreement + stream cipher |
| `crypto/SHA256.php` | SHA-256 from scratch; doubles as a counter-mode stream cipher |
| `crypto/HMAC.php` | HMAC-SHA256 for message authentication |
| `crypto/BigInt.php` | Large integer operations — wraps PHP GMP extension |
| `keymgmt/KeyManager.php` | Key generation, versioned storage, and retrieval |
| `keymgmt/key_registry.json` | Registry of active and historical key versions |

---

## Key Management

- Keys are **versioned** — each encrypted blob stores the `key_version` it was encrypted with
- After a key rotation, new writes use the new key; existing records are transparently decrypted with their stored version
- Public keys are stored in `key_registry.json`; private keys are stored as JSON files **outside the web root**
- `bootstrap_crypto.php` is the single entry point that loads all modules and exposes `getActiveKeys()` and `email_hash()`

### Privacy-Preserving Lookup

Email addresses are never stored in plaintext. Instead:
- The encrypted blob is stored in `email_enc`
- A SHA256 hash is stored in `email_hash` for login lookup
- This means a full database dump reveals no email addresses, even for the hash column

---

## Application Roles

- **Candidates** — register, build profile (all PII fields encrypted), browse and apply to jobs
- **Companies** — post jobs, review applicants, manage profile
- **Admins** — approve company registrations, manage job listings

All 16 PII fields in the `users` table are encrypted using `MultiEncrypt::encryptField()`. Passwords are hashed separately with bcrypt.

---

## Requirements

- PHP 5.6+ with the **GMP extension** (`extension=gmp` in `php.ini`) — required for all big-integer operations
- MySQL / MariaDB
- Apache (XAMPP recommended for local development)

---

## Setup

**1. Clone the repo**
```bash
git clone https://github.com/<your-username>/multiencrypt-job-portal-security.git
```

**2. Create the database**
```bash
mysql -u root -p -e "CREATE DATABASE jobportal;"
mysql -u root -p jobportal < database.sql
```

**3. Configure the database** — edit `db.php`:
```php
$conn = new mysqli("localhost", "root", "your_password", "jobportal");
```

**4. Move private keys outside the web root**

Copy `secure_keys/` to a directory outside your web root (e.g., `C:\xampp\secure_keys\`) and update the path in `keymgmt/KeyManager.php`.

**5. Start Apache + MySQL and navigate to:**
```
http://localhost/multiencrypt-job-portal-security/
```

**6. Verify the crypto stack works:**
```
http://localhost/multiencrypt-job-portal-security/test_crypto.php
```

---

## Key Rotation

```
http://localhost/multiencrypt-job-portal-security/keymgmt/rotate_keys.php
```

Generates a new RSA-2048 + ECC key pair, registers them as the new active version, and leaves all existing encrypted data intact (decryptable via their stored version number).

---

## Migrating Existing Plaintext Data

```
http://localhost/multiencrypt-job-portal-security/migrate_old_users.php
```

Encrypts any legacy plaintext email fields in the database using the current active key version.

---

## Project Structure

```
multiencrypt-job-portal-security/
├── crypto/             # Core cryptographic engine (RSA, ECC, ECIES, HMAC, SHA256)
├── keymgmt/            # Key management and rotation
├── secure_keys/        # Private keys — must be outside web root in production
├── admin/              # Demo app: admin dashboard
├── company/            # Demo app: company dashboard
├── user/               # Demo app: candidate dashboard
├── db.php              # Database connection config
├── bootstrap_crypto.php# Loads all crypto modules
├── database.sql        # Schema + seed data
└── test_crypto.php     # Smoke test for the full encrypt/decrypt round-trip
```

---

## License

This project is licensed under the [MIT License](LICENSE).
