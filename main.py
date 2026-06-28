# Cryptographic and utility libraries
import oqs
import os
import json
import base64
import bcrypt
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Constants for directory and algorithm selection
VAULT_DIR = "vaults"
LOG_FILE = "logs/security.log"
KYBER_ALG = "Kyber512"
DILITHIUM_ALG = "Dilithium2"

# Ensure required directories exist
os.makedirs(VAULT_DIR, exist_ok=True)
os.makedirs("logs", exist_ok=True)

# Utility Functions
def log_action(user, action, success, reason=""):
    """Log user actions to the security log"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "SUCCESS" if success else "FAILURE"
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {user} | {action} | {status} | {reason}\n")

def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password: str, hashed: bytes) -> bool:
    """Verify a bcrypt hashed password"""
    return bcrypt.checkpw(password.encode(), hashed)

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive AES key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=200_000, backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(key: bytes, data: bytes) -> dict:
    """Encrypt data using AES-GCM"""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

def decrypt_data(key: bytes, enc_dict: dict) -> bytes:
    """Decrypt data encrypted by AES-GCM"""
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(enc_dict["nonce"])
    ciphertext = base64.b64decode(enc_dict["ciphertext"])
    return aesgcm.decrypt(nonce, ciphertext, None)

def get_vault_path(username):
    """Generate path for a user's vault file"""
    return os.path.join(VAULT_DIR, f"{username}.json")

# PQCrypto Class (Kyber + Dilithium Handling)
class PQCrypto:
    """Post-Quantum Crypto operations using Kyber (KEM) and Dilithium (Signature)"""
    def __init__(self, kyber_alg=KYBER_ALG, dilithium_alg=DILITHIUM_ALG):
        self.kyber_alg = kyber_alg
        self.dilithium_alg = dilithium_alg

    def generate_kyber_keypair(self):
        kem = oqs.KeyEncapsulation(self.kyber_alg)
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        return public_key, secret_key

    def encapsulate(self, public_key):
        kem = oqs.KeyEncapsulation(self.kyber_alg)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext, secret_key):
        kem = oqs.KeyEncapsulation(self.kyber_alg, secret_key)
        return kem.decap_secret(ciphertext)

    def generate_dilithium_keypair(self):
        sig = oqs.Signature(self.dilithium_alg)
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
        return public_key, secret_key

    def sign(self, message: bytes, secret_key: bytes):
        signer = oqs.Signature(self.dilithium_alg, secret_key)
        return signer.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes):
        verifier = oqs.Signature(self.dilithium_alg)
        return verifier.verify(message, signature, public_key)

# Vault Class
class Vault:
    """Vault: Manage encrypted password entries with PQ encryption"""
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.crypto = PQCrypto()
        self.vault_path = get_vault_path(username)
        self.loaded = False
        self.data = {}

    def create_vault(self):
        if os.path.exists(self.vault_path):
            raise Exception("Vault already exists")

        password_hash = hash_password(self.password)
        kyber_pk, kyber_sk = self.crypto.generate_kyber_keypair()
        dil_pk, dil_sk = self.crypto.generate_dilithium_keypair()

        salt = os.urandom(16)
        aes_key = derive_key(self.password, salt)
        enc_kyber_sk = encrypt_data(aes_key, kyber_sk)
        enc_dil_sk = encrypt_data(aes_key, dil_sk)

        self.data = {
            "password_hash": base64.b64encode(password_hash).decode(),
            "salt": base64.b64encode(salt).decode(),
            "kyber_pk": base64.b64encode(kyber_pk).decode(),
            "dilithium_pk": base64.b64encode(dil_pk).decode(),
            "enc_kyber_sk": enc_kyber_sk,
            "enc_dilithium_sk": enc_dil_sk,
            "entries": []
        }
        with open(self.vault_path, "w") as f:
            json.dump(self.data, f, indent=4)

    def load_vault(self):
        if not os.path.exists(self.vault_path):
            raise Exception("Vault not found")

        with open(self.vault_path, "r") as f:
            self.data = json.load(f)

        stored_hash = base64.b64decode(self.data["password_hash"])
        if not verify_password(self.password, stored_hash):
            raise Exception("Invalid master password")
        self.loaded = True

    def _get_decryption_key(self):
        salt = base64.b64decode(self.data["salt"])
        return derive_key(self.password, salt)

    def add_entry(self, label, site_user, site_pass):
        aes_key = self._get_decryption_key()
        kyber_pk = base64.b64decode(self.data["kyber_pk"])
        dil_sk = decrypt_data(aes_key, self.data["enc_dilithium_sk"])

        ct, shared_secret = self.crypto.encapsulate(kyber_pk)
        entry_data = f"{site_user}:{site_pass}".encode()
        encrypted = encrypt_data(shared_secret, entry_data)

        data_to_sign = json.dumps(encrypted, sort_keys=True).encode()
        signature = self.crypto.sign(data_to_sign, dil_sk)
        enc_shared_secret = encrypt_data(aes_key, shared_secret)

        self.data["entries"].append({
            "label": label,
            "ciphertext": encrypted,
            "signature": base64.b64encode(signature).decode(),
            "ct": base64.b64encode(ct).decode(),
            "enc_shared_secret": enc_shared_secret
        })

        with open(self.vault_path, "w") as f:
            json.dump(self.data, f, indent=4)

    def get_entry(self, label):
        entry = next((e for e in self.data["entries"] if e["label"] == label), None)
        if not entry:
            raise Exception("Entry not found")

        aes_key = self._get_decryption_key()
        dil_pk = base64.b64decode(self.data["dilithium_pk"])

        shared_secret = decrypt_data(aes_key, entry["enc_shared_secret"])
        data_to_verify = json.dumps(entry["ciphertext"], sort_keys=True).encode()
        signature = base64.b64decode(entry["signature"])

        if not self.crypto.verify(data_to_verify, signature, dil_pk):
            raise Exception("Signature verification failed")

        decrypted = decrypt_data(shared_secret, entry["ciphertext"])
        site_user, site_pass = decrypted.decode().split(":", 1)
        return {"label": label, "username": site_user, "password": site_pass}

    def list_entries(self):
        return [e["label"] for e in self.data["entries"]]

    def delete_entry(self, label):
        self.data["entries"] = [e for e in self.data["entries"] if e["label"] != label]
        with open(self.vault_path, "w") as f:
            json.dump(self.data, f, indent=4)

# Lockout Features
LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=5)

def is_login_blocked(username):
    entry = LOGIN_ATTEMPTS.get(username)
    if not entry:
        return False
    attempts, last_attempt_time = entry
    if attempts < MAX_ATTEMPTS:
        return False
    if datetime.now() - last_attempt_time > LOCKOUT_DURATION:
        reset_login_attempts(username)
        return False
    return True

def increment_login_attempt(username):
    now = datetime.now()
    if username in LOGIN_ATTEMPTS:
        attempts, _ = LOGIN_ATTEMPTS[username]
        LOGIN_ATTEMPTS[username] = (attempts + 1, now)
    else:
        LOGIN_ATTEMPTS[username] = (1, now)

def reset_login_attempts(username):
    if username in LOGIN_ATTEMPTS:
        del LOGIN_ATTEMPTS[username]

def get_remaining_lock_time(username):
    """Returns remaining lockout time in minutes (int), or None if not blocked"""
    entry = LOGIN_ATTEMPTS.get(username)
    if not entry:
        return None
    attempts, last_attempt_time = entry
    if attempts >= MAX_ATTEMPTS:
        elapsed = datetime.now() - last_attempt_time
        remaining = LOCKOUT_DURATION - elapsed
        if remaining.total_seconds() > 0:
            return remaining.seconds // 60
    return None

# Backup and Restore
def backup_vault(username):
    source = get_vault_path(username)
    backup = source + ".bak"
    if not os.path.exists(source):
        print(" Vault file not found.")
        return
    with open(source, "rb") as f_src, open(backup, "wb") as f_bak:
        f_bak.write(f_src.read())
    print(f" Backup created: {backup}")

def restore_vault(username):
    source = get_vault_path(username)
    backup = source + ".bak"
    if not os.path.exists(backup):
        print(" Backup file not found.")
        return
    with open(backup, "rb") as f_bak, open(source, "wb") as f_src:
        f_src.write(f_bak.read())
    print(f" Vault restored from backup: {backup}")

# Integrity Check
VAULT_SIGNATURES = {}

def sign_vault_integrity(vault_obj):
    aes_key = vault_obj._get_decryption_key()
    dil_sk = decrypt_data(aes_key, vault_obj.data["enc_dilithium_sk"])
    with open(vault_obj.vault_path, "rb") as f:
        vault_data = f.read()
    pq = vault_obj.crypto
    signature = pq.sign(vault_data, dil_sk)
    VAULT_SIGNATURES[vault_obj.username] = signature
    print(" Vault signature generated and saved.")

def verify_vault_integrity(vault_obj):
    if vault_obj.username not in VAULT_SIGNATURES:
        print(" No previous signature found for integrity check.")
        return
    with open(vault_obj.vault_path, "rb") as f:
        current_data = f.read()
    pq = vault_obj.crypto
    dil_pk = base64.b64decode(vault_obj.data["dilithium_pk"])
    valid = pq.verify(current_data, VAULT_SIGNATURES[vault_obj.username], dil_pk)
    if valid:
        print(" Vault integrity verified with Dilithium signature.")
    else:
        print(" Vault integrity check FAILED!")

# CLI Interface
def print_banner():
    print("\n" + "=" * 60)
    print(" QUANTUM-SAFE PASSWORD VAULT")
    print("   Kyber + Dilithium Post-Quantum Protection")
    print("=" * 60 + "\n")

def main_menu():
    print("\n MAIN MENU")
    print("-" * 40)
    print("1. Create New Vault")
    print("2. Load Existing Vault")
    print("3. Add New Password Entry")
    print("4. Retrieve Password Entry")
    print("5. List All Stored Entries")
    print("6. Delete an Entry")
    print("7. View Security Log")
    print("8. Exit")
    print("9. Backup Vault")
    print("10. Restore Vault")
    print("11. Verify Vault Integrity")
    print("-" * 40)

def view_log():
    if not os.path.exists(LOG_FILE):
        print("📭 No security log available.")
        return
    print("\n" + "=" * 60)
    print(" SECURITY LOG (Last 20 Entries)")
    print("=" * 60)
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
        for line in lines[-20:]:
            print(line.strip())
    print("=" * 60 + "\n")

def run_cli():
    print_banner()
    vault = None
    while True:
        main_menu()
        choice = input("\nSelect an option (1-11): ").strip()

        if choice == "1":
            print("\n CREATE NEW VAULT")
            username = input("Username: ").strip()
            password = input("Master Password: ").strip()
            try:
                vault = Vault(username, password)
                vault.create_vault()
                sign_vault_integrity(vault)
            except Exception as e:
                print(f" Error: {e}")

        elif choice == "2":
            print("\n LOAD EXISTING VAULT")
            username = input("Username: ").strip()
            if is_login_blocked(username):
                wait = get_remaining_lock_time(username)
                print(f" Too many failed attempts. Try again in {wait} minute(s).")
                continue
            password = input("Master Password: ").strip()
            try:
                vault = Vault(username, password)
                vault.load_vault()
                print(" Vault loaded successfully.")
                reset_login_attempts(username)
            except Exception as e:
                increment_login_attempt(username)
                print(f" Error: {e}")
                vault = None

        elif choice == "3":
            if not vault or not vault.loaded:
                print(" Please load your vault first.")
                continue
            print("\n➕ ADD NEW PASSWORD ENTRY")
            label = input("Label (e.g., 'Facebook'): ").strip()
            site_user = input("Site Username: ").strip()
            site_pass = input("Site Password: ").strip()
            try:
                vault.add_entry(label, site_user, site_pass)
                sign_vault_integrity(vault)
            except Exception as e:
                print(f" Error: {e}")

        elif choice == "4":
            print("\n RE-AUTHENTICATION REQUIRED")
            username = input("Username: ").strip()
            password = input("Master Password: ").strip()
            try:
                temp_vault = Vault(username, password)
                temp_vault.load_vault()
                label = input("Label: ").strip()
                entry = temp_vault.get_entry(label)
                print("\n Retrieved Entry:")
                print("=" * 40)
                print(f"Label:    {entry['label']}")
                print(f"Username: {entry['username']}")
                print(f"Password: {entry['password']}")
                print("=" * 40)
            except Exception as e:
                print(f" Error: {e}")

        elif choice == "5":
            if not vault or not vault.loaded:
                print(" Please load your vault first.")
                continue
            try:
                entries = vault.list_entries()
                if entries:
                    print("\n STORED ENTRIES:")
                    for i, label in enumerate(entries, 1):
                        print(f"  {i}. {label}")
                else:
                    print("📭 No entries found.")
            except Exception as e:
                print(f" Error: {e}")

        elif choice == "6":
            if not vault or not vault.loaded:
                print(" Please load your vault first.")
                continue
            print("\n DELETE ENTRY")
            label = input("Label to delete: ").strip()
            confirm = input(f"Are you sure you want to delete '{label}'? (yes/no): ").lower()
            if confirm == "yes":
                try:
                    vault.delete_entry(label)
                    sign_vault_integrity(vault)
                except Exception as e:
                    print(f" Error: {e}")
            else:
                print(" Deletion cancelled.")

        elif choice == "7":
            view_log()

        elif choice == "8":
            print("\n Exiting vault. Stay safe!")
            break

        elif choice == "9":
            if not vault or not vault.loaded:
                print(" Please load your vault first.")
                continue
            backup_vault(vault.username)

        elif choice == "10":
            if not vault or not vault.loaded:
                print(" Please load your vault first.")
                continue
            restore_vault(vault.username)

        elif choice == "11":
            if not vault or not vault.loaded:
                print(" Please load your vault first.")
                continue
            verify_vault_integrity(vault)

        else:
            print(" Invalid option. Please try again.")

if __name__ == "__main__":
    run_cli()
