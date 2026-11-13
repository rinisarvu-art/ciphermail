# CipherMail — Zero-Knowledge End-to-End Encrypted (E2EE) Webmail System

**Project Title:** CipherMail: A Zero-Knowledge End-to-End Encrypted Webmail System with Dual-Vault Architecture and Plausible Deniability  
**Domain:** Cybersecurity, Cryptography, Web Technologies  
**Category:** Final Year Engineering Project  

---

## 1. Project Overview & Abstract

Standard internet mail (SMTP/IMAP) transmits and stores messages in plaintext on cloud servers. This exposes confidential communications to rogue database administrators, unauthorized surveillance, and data breaches.

**CipherMail** solves this problem by enforcing a **Zero-Knowledge Architecture**:
- All encryption, decryption, and key generation occur strictly inside the client's browser using the native **W3C WebCrypto API** (`window.crypto.subtle`).
- The backend server and database only ever store encrypted ciphertext blobs (Base64) and public keys. 
- Even with root database access, a malicious attacker or server admin cannot read email subjects, message bodies, or attachments.

---

## 2. Advanced & Unique Features (Beyond Normal Email)

| Feature | Description | Academic / Real-World Value |
| :--- | :--- | :--- |
| **Dual-Vault Architecture (Normal vs Shadow Vault)** | Two distinct modes: Standard Workspace for everyday emails, and a covert **Shadow Vault** for high-classification communication. | Implements **Plausible Deniability** |
| **Covert Trigger Mechanism** | The Shadow Vault is completely invisible. Typing `:vault:open` in the search bar triggers the secret access gate. | Protects against shoulder-surfing and discovery |
| **Emergency Panic Lock (ESC Key)** | Pressing `Escape` or clicking the Panic button instantly locks the vault, clears decrypted keys from RAM, and returns to normal inbox. | Immediate physical threat response |
| **Duress / Decoy Password** | If a user is forced to reveal their password under coercion, entering their Duress Password displays a harmless, decoy inbox. | Anti-coercion security |
| **Hybrid Envelope Encryption** | Combines **AES-256-GCM** (symmetric) for body & attachments with **RSA-OAEP 2048-bit** (asymmetric) for session key exchange. | High performance + Strong security |
| **Digital Signatures (Integrity & Non-Repudiation)** | Every email is signed with **ECDSA (P-256)**. Tampered emails trigger a prominent Red Alert in the receiver's UI. | Prevents spoofing and man-in-the-middle alterations |
| **True Ephemeral Burn-After-Reading** | Configurable timer or single-view destruct. Keys are permanently shredded from the server upon viewing. | GDPR right-to-be-forgotten compliance |
| **Dynamic Anti-Leak Watermark** | Sensitive vault emails render a semi-transparent canvas watermark with the receiver's email, IP, and timestamp. | Traces and deters camera/screenshot leaks |
| **Zero-Cache Attachment Viewer** | Attachments (PDFs, images) are decrypted directly in browser RAM (`createObjectURL`) without leaving forensic traces on the disk. | Forensics countermeasure |
| **Live Examiner Audit & Entropy Benchmark** | In-app modal displaying raw database ciphertext and calculating real-time Shannon Entropy (up to 8.00 bits/byte). | Perfect for viva evaluation & report graphs |

---

## 3. System Architecture & Cryptographic Flow

```
+-------------------------------------------------------------------------+
|                          BROWSER (CLIENT-SIDE)                          |
|                                                                         |
|  1. Generate RSA-2048 (Encryption) + ECDSA P-256 (Signature) Keypairs  |
|  2. User Password + Salt ---> PBKDF2 (100k rounds) ---> Master Key AES   |
|  3. Private Key Encrypted with Master Key before syncing to server       |
+-------------------------------------------------------------------------+
                                    │
                                    ▼ (Zero-Knowledge Sync)
+-------------------------------------------------------------------------+
|                          SERVER & DATABASE                              |
|                                                                         |
|  Stores ONLY:                                                           |
|  - Public Keys (RSA & ECDSA)                                            |
|  - Encrypted Private Key Vault                                          |
|  - Encrypted Email Payloads (Ciphertext + Nonce/IV + Signatures)       |
+-------------------------------------------------------------------------+
```

---

## 4. How to Run the Project

### Prerequisites
- Python 3.10+ (Python 3.14 installed on your system)
- Modern web browser (Chrome, Edge, Firefox, Brave)

### Execution Steps
1. Open PowerShell or Command Prompt.
2. Navigate to the project directory:
   ```powershell
   cd C:\Users\ELCOT\.gemini\antigravity\scratch\ciphermail
   ```
3. Run the application:
   ```powershell
   python app.py
   ```
   *(Or simply double-click `run.bat`)*
4. Open your browser and go to:
   ```
   http://127.0.0.1:5000
   ```

---

## 5. Viva / Presentation Demo Script (Step-by-Step for Examiners)

To score maximum marks during your project evaluation, follow this exact sequence:

### Step 1: User Registration & Key Generation
1. Click **Register** on the modal.
2. Enter username: `alice`, email: `alice@ciphermail.local`, password: `Password123!`.
3. Enter Duress Password: `PanicPassword123!`.
4. Click **Register & Generate Cryptographic Keys**.
   - *Explain to Examiner:* "Sir, notice how the browser pauses for 0.5s: it is generating a 2048-bit RSA keypair and an ECDSA signature keypair locally using WebCrypto API. The private key is encrypted with PBKDF2 before reaching the server."

### Step 2: Register a Second User
1. Open an Incognito Window (or a second browser tab).
2. Register `bob` (`bob@ciphermail.local`, password: `Password123!`).

### Step 3: Sending an Encrypted Email (Alice ➔ Bob)
1. Back on Alice's window, click **New Encrypted Mail**.
2. Recipient: `bob@ciphermail.local`.
3. Subject: `Project Top Secret Specs`.
4. Body: `The cryptographic keys are verified. Proceed with deployment.`
5. Attach a file (image or document) and check **Classified (Route to Shadow Vault)** and **🔥 Burn-After-Reading**.
6. Click **Encrypt & Send**.

### Step 4: Prove Zero-Knowledge Storage (The "Showstopper")
1. In the top navigation bar, click **Examiner Audit & Benchmarks**.
2. Point to the table:
   - "Sir, as you can see from our live database inspection, the email subject, body, session key, and file attachment are completely scrambled Base64 ciphertext. The server administrator cannot read any message."
3. Click **Run Test Now** under Shannon Entropy to demonstrate that the ciphertext achieves optimal high randomness (~7.98 / 8.00 bits).

### Step 5: Unlocking the Secret Shadow Vault
1. In Bob's browser, show the standard inbox (empty or normal).
2. In the top search bar, type:
   ```
   :vault:open
   ```
   and press **Enter**.
3. The **Shadow Vault Access Gate** modal appears!
4. Enter any security passphrase and click **Unlock Shadow Vault**.
5. The UI transforms into the Red/Dark **Classified Mode**.
6. Bob clicks on Alice's classified email:
   - The message decrypts live in-memory.
   - The **"🛡️ Cryptographically Verified"** badge confirms Alice's digital signature.
   - The **Dynamic Anti-Leak Watermark** displays Bob's email and timestamp across the screen.
   - The Burn-After-Reading mechanism shreds the key from the database upon viewing!

### Step 6: The Panic Button (Emergency Response)
1. While reading the confidential email in the Shadow Vault, press the **`ESC` key** on your keyboard (or click **🚨 PANIC LOCK**).
2. The UI instantly snaps back to the Standard Workspace and clears all classified data from memory.

### Step 7: Decoy Duress Mode (Anti-Coercion)
1. Log out.
2. Log in using Alice's Duress Password: `PanicPassword123!`.
3. The system opens a fake **Decoy Inbox** containing innocent shopping and newsletter emails. The real confidential inbox remains hidden.

---

## 6. Directory Structure

```
ciphermail/
├── app.py                  # Flask backend (Zero-Knowledge API, SQLite ORM, Ephemeral worker)
├── requirements.txt        # Python dependencies
├── run.bat                 # 1-click startup script for Windows
├── README.md               # Complete project documentation & viva guide
├── templates/
│   └── index.html          # Responsive Webmail UI & Modals
└── static/
    ├── css/
    │   └── style.css       # Dual-Vault UI styling, watermarks, panic animations
    └── js/
        ├── crypto.js       # Native WebCrypto API (AES-GCM, RSA-OAEP, ECDSA, PBKDF2)
        └── app.js          # State manager, search trigger, panic key, in-memory decryptor
```
