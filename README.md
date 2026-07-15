# Cryptographic-Protocol-Implementation-Network-Security-Threat-Analysis

# CampusConnect Cryptographic Protocol Implementation & Network Security Threat Analysis

This repository contains:

- `rsa.py` – RSA key generation, encryption, and decryption implementation.
- `dh.py` – Diffie-Hellman key exchange implementation.
- `README.md` – This file, containing security-principle mapping and threat-model analysis.

## Test Cases

### RSA

The script runs two test cases:

1. **Test case (a)** (from the worked example):  
   - `p = 3`, `q = 11`, `e = 3`, `m = 4`  
   - Expected: decrypted message equals original `m = 4`.

2. **Test case (b)** (additional):  
   - `p = 7`, `q = 13`, `e = 5`, `m = 10`  
   - Expected: decrypted message equals original `m = 10`.

Run:

```bash
python3 rsa.py
```

### Diffie-Hellman

The script runs two test cases:

1. **Test case (a)** (from the worked example):  
   - `p = 29`, `alpha = 2`, `a = 5`, `b = 12`  
   - Expected: both computed shared secrets `K` are equal.

2. **Test case (b)** (additional):  
   - `p = 37`, `alpha = 2`, `a = 7`, `b = 15`  
   - Expected: both computed shared secrets `K` are equal.

Run:

```bash
python3 dh.py
```

---

## Security-Principle Mapping

### RSA

**Security principles addressed:**

- **Confidentiality** – RSA encryption (`c = m^e mod n`, `m = c^d mod n`) ensures that only someone with the private key `d` can recover the plaintext `m` from the ciphertext `c`. This protects sensitive data (e.g., login tokens, personal information) from being read by unauthorized parties.
- **Authentication & Non‑repudiation** – When used for digital signatures (signing with the private key and verifying with the public key), RSA provides authentication (proving the signer’s identity) and non‑repudiation (the signer cannot later deny having signed the message).

In this assignment, RSA is used primarily for **confidentiality** via encryption/decryption, but the same key pair can also support signatures for authentication and non‑repudiation.

### Diffie-Hellman

**Security principles addressed:**

- **Confidentiality** – Diffie-Hellman does not directly encrypt data; instead, it allows two parties to derive a shared secret `K` over an insecure channel. This secret can then be used as a key for symmetric encryption (e.g., AES), enabling confidential communication.
- **Authentication (partial)** – Basic Diffie-Hellman as implemented here does not provide authentication; it is vulnerable to man‑in‑the‑middle attacks unless augmented with signatures or certificates. However, the protocol’s purpose is to establish a shared secret that can later be combined with authenticated key exchange mechanisms.

---

## Why Diffie-Hellman Is a Key Exchange Protocol, Not an Encryption Algorithm

Diffie-Hellman is classified as a **key exchange protocol** because its primary goal is to allow two parties to jointly compute a shared secret `K` using their private keys and exchanged public values, without ever transmitting `K` itself. The protocol does not transform arbitrary messages into ciphertext; it only produces a secret that can later be used as a symmetric key for encryption.

In contrast, **RSA** is a full public‑key cryptosystem that can:

- Generate a public/private key pair.
- Directly **encrypt and decrypt** messages using `c = m^e mod n` and `m = c^d mod n`.
- Also be used for **digital signatures**, providing authentication and non‑repudiation.

Thus, RSA can perform both key-pair generation and direct encryption/decryption, while Diffie-Hellman only provides a mechanism to agree on a shared secret.

---

## Threat-Model Write‑up

### (a) Firewall Placement, Type, and Rule

**Placement:**  
Place the firewall between CampusConnect’s internal network (where the web servers, database servers, and application servers reside) and the external Internet. This is typically at the edge of the campus network, before traffic reaches the server subnet.

**Type:**  
Use a **hardware firewall** (e.g., a dedicated network appliance or router with firewall capabilities) as the primary boundary defense, complemented by **software firewalls** on each server for host-level filtering.

**Specific traffic-filtering rule:**  
Enforce a rule that:

- **Allows** inbound TCP traffic on port **443** (HTTPS) from any source IP to the CampusConnect web server.
- **Denies** all other inbound traffic to the server subnet except from trusted management IPs.

Example rule (conceptual):

```text
ALLOW tcp any -> web-server-ip:443
DENY  tcp any -> web-server-ip:!*443
```

This ensures that only secure HTTP traffic is accepted, while blocking unencrypted HTTP (port 80) and other potentially dangerous services.

---

### (b) IDS Choice: Host-based, Network-based, or Both

**Recommendation:** Deploy **both** a Host-based IDS (HIDS) and a Network-based IDS (NIDS).

- **Host-based IDS (HIDS):**  
  - *Justification:* HIDS can detect attacks targeting the OS and applications on individual servers (e.g., unauthorized file changes, suspicious processes, log tampering) that a network monitor might not see, especially after encryption.
- **Network-based IDS (NIDS):**  
  - *Justification:* NIDS can detect broad network-layer attacks (e.g., scanning, Muster of malicious connection attempts, protocol anomalies) across the entire campus network, including traffic patterns that HIDS cannot observe.

Using both provides complementary coverage: NIDS for network-wide threats and HIDS for deep server-level detection.

---

### (c) HTTP vs HTTPS for the Login Page

**Recommendation:** CampusConnect’s login page must use **HTTPS**, not plain HTTP.

**Specific vulnerability prevented:**  
HTTPS prevents **credential sniffing** (eavesdropping on usernames and passwords) and **session hijacking** by encrypting the entire HTTP session, including login credentials and session tokens.

Without HTTPS, an attacker on the same network or with access to network infrastructure could capture clear-text passwords and session cookies, leading to unauthorized account access.

---

### (d) Authentication Design with Least Privilege and Multi-Factor Authentication

**Authentication factors:**

CampusConnect should implement **multi-factor authentication (MFA)** with at least two of the following:

1. **Factor 1 – Knowledge:** Username/password (or a strong password policy).
2. **Factor 2 – Possession:** A one-time token from a mobile app (e.g., TOTP) or SMS code.
3. **Factor 3 – Inherence:** Optional biometric factor (e.g., fingerprint) for high-privilege roles.

For regular users, Factor 1 + Factor 2 is sufficient.

**Roles and permissions (least privilege):**

- **Students:**
  - Can view their own courses, grades, and enrollments.
  - Can update limited personal information (e.g., contact details).
  - Cannot access other students’ data or instructor/admin features.

- **Instructors:**
  - Can manage courses they teach (add materials, grades, view enrolled students).
  - Can view data only for their own courses.
  - Cannot modify system settings or access other instructors’ courses.

- **Administrators:**
  - Can manage user accounts, roles, and system configuration.
  - Can access audit logs and security events.
  - Get MFA with stronger factors (e.g., push-based token + optional biometric) and stricter access controls.

Each role is granted only the permissions necessary to perform their duties, minimizing the impact of accidental misuse or compromised credentials.

---

### (e) Plausible Attack Against CampusConnect

**Attack description:**  
An attacker monitors network traffic on the campus Wi‑Fi and captures unencrypted HTTP requests to CampusConnect’s login page. By inspecting these packets, they extract the user’s username and password in clear text, then use them to log in as that user.

**Classification:**  
This is a **passive** attack.

**Justification:**  
The attacker does not modify or inject traffic; they only observe and record existing communications, which is the defining characteristic of a passive attack (eavesdropping).
