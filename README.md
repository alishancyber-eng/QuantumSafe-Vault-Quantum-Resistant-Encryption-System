# QuantumSafe Vault: Quantum-Resistant Encryption System

## Project Overview
Current password vaults rely on classical security (like RSA), which is highly vulnerable to the emerging threat of Quantum Computers and "Harvest Now, Decrypt Later" attacks. **QuantumSafe Vault** is a Next-Generation Password Vault developed to store credentials securely using Post-Quantum Cryptography (PQC).

This was developed as a 7th-semester project at the Department of Information and Communication Engineering, The Islamia University of Bahawalpur. 
**Team:** Ali Shan, Muhammad Ahmad, Hassaan Iqbal
**Supervisor:** Dr. Abdul Rehman Chishti

## Core Features
* **Confidentiality (Kyber-512):** Utilizes NIST-standardized key encapsulation to secure user credentials against quantum decryption attacks.
* **Integrity (Dilithium-2):** Integrates digital signatures to detect unauthorized modifications to the vault file.
* **Hybrid Encryption:** Combines Post-Quantum keys with AES-GCM for robust, fast data encryption.
* **Access Control:** Prevents unauthorized access via a Brute-Force Lockout Mechanism (5 failed attempts = 5-minute block).
* **Reliability:** Includes secure Backup and Restore features for disaster recovery.

## Future Work
* GUI Development (Desktop Interface)
* Cloud Sync for encrypted data
* Biometric Login Support (Fingerprint/FaceID)
* Android/iOS Mobile Application
