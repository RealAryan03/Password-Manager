# Password Manager Implementation
# A comprehensive secure password manager built in Python
# Author: AI Assistant for Cybersecurity Project
# Version: 1.0

import os
import sys
import json
import hashlib
import secrets
import string
import getpass
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class PasswordManager:
    """
    A secure password manager class that handles encryption, storage, and retrieval of passwords.

    Features:
    - AES-256 encryption using Fernet
    - Master password protection with PBKDF2 key derivation
    - Secure password generation
    - JSON-based encrypted storage
    - Audit logging
    - Password strength validation
    """

    def __init__(self, vault_file="password_vault.json", log_file="audit.log"):
        self.vault_file = vault_file
        self.log_file = log_file
        self.cipher = None
        self.logged_in = False
        self.master_password_hash = None

        # Initialize vault file if it doesn't exist
        if not os.path.exists(self.vault_file):
            self._create_vault()

    def _create_vault(self):
        """Create an empty vault file"""
        vault_structure = {
            "metadata": {
                "created": datetime.now().isoformat(),
                "version": "1.0"
            },
            "master_hash": None,
            "salt": None,
            "passwords": {}
        }
        with open(self.vault_file, 'w') as f:
            json.dump(vault_structure, f)
        self._log_activity("Vault created")

    def _derive_key(self, password, salt):
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def _log_activity(self, activity):
        """Log activities for audit trail"""
        timestamp = datetime.now().isoformat()
        with open(self.log_file, 'a') as f:
            f.write(f"{timestamp} - {activity}\n")

    def _validate_password_strength(self, password):
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        score = sum([has_upper, has_lower, has_digit, has_special])

        if score < 3:
            return False, "Password must contain at least 3 of: uppercase, lowercase, digit, special character"

        return True, "Strong password"

    def set_master_password(self, password):
        """Set or change master password"""
        is_valid, message = self._validate_password_strength(password)
        if not is_valid:
            return False, message

        # Generate salt
        salt = os.urandom(16)

        # Hash master password
        master_hash = hashlib.sha256(password.encode()).hexdigest()

        # Load vault
        with open(self.vault_file, 'r') as f:
            vault = json.load(f)

        # Update vault
        vault["master_hash"] = master_hash
        vault["salt"] = base64.b64encode(salt).decode()

        # Save vault
        with open(self.vault_file, 'w') as f:
            json.dump(vault, f)

        self._log_activity("Master password set")
        return True, "Master password set successfully"

    def login(self, password):
        """Login with master password"""
        # Load vault
        with open(self.vault_file, 'r') as f:
            vault = json.load(f)

        if vault["master_hash"] is None:
            return False, "No master password set. Please set a master password first."

        # Verify password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash != vault["master_hash"]:
            self._log_activity("Failed login attempt")
            return False, "Invalid master password"

        # Initialize cipher
        salt = base64.b64decode(vault["salt"])
        key = self._derive_key(password, salt)
        self.cipher = Fernet(key)
        self.logged_in = True

        self._log_activity("Successful login")
        return True, "Login successful"

    def logout(self):
        """Logout and clear cipher"""
        self.cipher = None
        self.logged_in = False
        self._log_activity("User logged out")

    def generate_password(self, length=16, use_symbols=True):
        """Generate a secure random password"""
        if not self.logged_in:
            return None, "Please login first"

        alphabet = string.ascii_letters + string.digits
        if use_symbols:
            alphabet += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        self._log_activity(f"Password generated (length: {length})")
        return password, "Password generated successfully"

    def add_password(self, website, username, password, notes=""):
        """Add a password to the vault"""
        if not self.logged_in:
            return False, "Please login first"

        # Load vault
        with open(self.vault_file, 'r') as f:
            vault = json.load(f)

        # Encrypt password data
        password_data = {
            "username": username,
            "password": password,
            "notes": notes,
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat()
        }

        encrypted_data = self.cipher.encrypt(json.dumps(password_data).encode())
        vault["passwords"][website] = base64.b64encode(encrypted_data).decode()

        # Save vault
        with open(self.vault_file, 'w') as f:
            json.dump(vault, f)

        self._log_activity(f"Password added for {website}")
        return True, "Password added successfully"

    def get_password(self, website):
        """Retrieve a password from the vault"""
        if not self.logged_in:
            return None, "Please login first"

        # Load vault
        with open(self.vault_file, 'r') as f:
            vault = json.load(f)

        if website not in vault["passwords"]:
            return None, "Website not found in vault"

        try:
            # Decrypt password data
            encrypted_data = base64.b64decode(vault["passwords"][website])
            decrypted_data = self.cipher.decrypt(encrypted_data)
            password_data = json.loads(decrypted_data.decode())

            self._log_activity(f"Password retrieved for {website}")
            return password_data, "Password retrieved successfully"

        except Exception as e:
            self._log_activity(f"Failed to retrieve password for {website}: {str(e)}")
            return None, "Failed to decrypt password data"

    def list_websites(self):
        """List all websites in the vault"""
        if not self.logged_in:
            return [], "Please login first"

        # Load vault
        with open(self.vault_file, 'r') as f:
            vault = json.load(f)

        websites = list(vault["passwords"].keys())
        self._log_activity("Listed all websites")
        return websites, "Websites listed successfully"

    def update_password(self, website, username=None, password=None, notes=None):
        """Update an existing password entry"""
        if not self.logged_in:
            return False, "Please login first"

        # First get existing data
        existing_data, message = self.get_password(website)
        if existing_data is None:
            return False, message

        # Update fields if provided
        if username is not None:
            existing_data["username"] = username
        if password is not None:
            existing_data["password"] = password
        if notes is not None:
            existing_data["notes"] = notes

        existing_data["modified"] = datetime.now().isoformat()

        # Save updated data
        with open(self.vault_file, 'r') as f:
            vault = json.load(f)

        encrypted_data = self.cipher.encrypt(json.dumps(existing_data).encode())
        vault["passwords"][website] = base64.b64encode(encrypted_data).decode()

        with open(self.vault_file, 'w') as f:
            json.dump(vault, f)

        self._log_activity(f"Password updated for {website}")
        return True, "Password updated successfully"

    def delete_password(self, website):
        """Delete a password from the vault"""
        if not self.logged_in:
            return False, "Please login first"

        # Load vault
        with open(self.vault_file, 'r') as f:
            vault = json.load(f)

        if website not in vault["passwords"]:
            return False, "Website not found in vault"

        del vault["passwords"][website]

        # Save vault
        with open(self.vault_file, 'w') as f:
            json.dump(vault, f)

        self._log_activity(f"Password deleted for {website}")
        return True, "Password deleted successfully"


def main():
    """Main function to run the password manager CLI"""
    pm = PasswordManager()

    print("=== Secure Password Manager ===")
    print("Welcome to the Password Manager!")

    # Check if master password is set
    with open(pm.vault_file, 'r') as f:
        vault = json.load(f)

    if vault["master_hash"] is None:
        print("\nNo master password found. Please set one.")
        while True:
            password = getpass.getpass("Enter master password: ")
            confirm = getpass.getpass("Confirm master password: ")

            if password != confirm:
                print("Passwords don't match. Try again.")
                continue

            success, message = pm.set_master_password(password)
            if success:
                print(message)
                break
            else:
                print(f"Error: {message}")

    # Login
    while not pm.logged_in:
        password = getpass.getpass("Enter master password: ")
        success, message = pm.login(password)
        if success:
            print(message)
        else:
            print(f"Error: {message}")

    # Main menu
    while True:
        print("\n=== Main Menu ===")
        print("1. Add password")
        print("2. Get password") 
        print("3. List websites")
        print("4. Update password")
        print("5. Delete password")
        print("6. Generate password")
        print("7. Logout")
        print("8. Exit")

        choice = input("Select option (1-8): ").strip()

        if choice == '1':
            website = input("Website: ").strip()
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            notes = input("Notes (optional): ").strip()

            success, message = pm.add_password(website, username, password, notes)
            print(f"Result: {message}")

        elif choice == '2':
            website = input("Website: ").strip()
            data, message = pm.get_password(website)

            if data:
                print(f"Username: {data['username']}")
                print(f"Password: {data['password']}")
                print(f"Notes: {data['notes']}")
                print(f"Created: {data['created']}")
                print(f"Modified: {data['modified']}")
            else:
                print(f"Error: {message}")

        elif choice == '3':
            websites, message = pm.list_websites()
            print(f"\nWebsites in vault ({len(websites)}):")
            for website in websites:
                print(f"  - {website}")

        elif choice == '4':
            website = input("Website to update: ").strip()
            print("Leave blank to keep current value")
            username = input("New username: ").strip() or None
            password = getpass.getpass("New password: ") or None
            notes = input("New notes: ").strip() or None

            success, message = pm.update_password(website, username, password, notes)
            print(f"Result: {message}")

        elif choice == '5':
            website = input("Website to delete: ").strip()
            confirm = input(f"Delete password for {website}? (y/N): ").strip().lower()

            if confirm == 'y':
                success, message = pm.delete_password(website)
                print(f"Result: {message}")
            else:
                print("Deletion cancelled")

        elif choice == '6':
            try:
                length = int(input("Password length (default 16): ") or "16")
                use_symbols = input("Include symbols? (Y/n): ").strip().lower() != 'n'

                password, message = pm.generate_password(length, use_symbols)
                if password:
                    print(f"Generated password: {password}")
                else:
                    print(f"Error: {message}")
            except ValueError:
                print("Invalid length. Please enter a number.")

        elif choice == '7':
            pm.logout()
            print("Logged out successfully")
            break

        elif choice == '8':
            pm.logout()
            print("Goodbye!")
            sys.exit(0)

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
