import os
import sys
from pathlib import Path
# Adjust import path for backend modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from Backend.CryptoUtils import CryptoPaladin as cp
from Backend.CryptoUtils.CryptoPaladinExceptions import InvalidPasswordException, KeyFileNotFoundException
from Backend.Repository.SQLiteRepository import SQLiteRepository
from Backend.Entities.Password import Password
class PaladinVaultController:
    def __init__(self):
        self.derived_key = None
        self.db_repository = None
        self.key_file_path = None

    def login(self, master_password: str, key_file_path: str) -> bool:
        """
        Authenticates the user using the master password and key file.
        Initializes the database repository upon successful authentication.

        Args:
            master_password: The user's master password.
            key_file_path: Path to the key file (e.g., salt.bin or vault.key).

        Returns:
            True if login is successful, False otherwise.

        Raises:
            KeyFileNotFoundException: If the key file is not found.
            InvalidPasswordException: If the master password is incorrect.
            Exception: For other potential errors during key loading or derivation.
        """
        if not os.path.exists(key_file_path):
            raise KeyFileNotFoundException(f"Key file not found at: {key_file_path}")

        try:
            # 1. Load the key and salt from the key file
            loaded_key_data, salt = cp.load_key(key_file_path)

            # 2. Verify the master password against the loaded key (which is actually a hash) and salt
            # cp.verify_key internally re-derives the key from master_password and salt,
            # then compares it with loaded_key_data.
            if not cp.verify_key(input=master_password, key=loaded_key_data, salt=salt):
                # This path should ideally be caught by verify_key raising InvalidPasswordException
                raise InvalidPasswordException("Master password verification failed.")

            # 3. If verification is successful, derive the actual encryption key for database operations
            # This derived key is what will be used for encrypting/decrypting data in the database.
            self.derived_key, _ = cp.derive_key(input=master_password, salt=salt) # Use the same salt

            # 4. (Optional but recommended) Initialize SQLiteRepository here if login is successful
            # self.initialize_repository() # You'll need to decide where your DB file is stored.
            self.key_file_path=key_file_path
            print("Login successful. Encryption key derived.")

            self.initialize_repository()

            return True

        except InvalidPasswordException:
            # Re-raise to be caught by the UI
            raise
        except FileNotFoundError: # Should be caught by the initial os.path.exists check
            raise KeyFileNotFoundException(f"Key file not found: {key_file_path}")
        except Exception as e:
            # Catch-all for other potential errors during crypto operations
            print(f"An unexpected error occurred during login: {e}")
            raise Exception(f"Login process failed: {e}")


    def initialize_repository(self):
        """
        Initializes the SQLiteRepository with the derived key.
        This should be called after a successful login.
        """
        if not self.derived_key:
            raise Exception("Derived key is not available. Login must be successful first.")

        self.db_repository = SQLiteRepository(key=self.derived_key)
        print(f"Database repository initialized with path: {self.db_repository.get_db_path()}")
        # You might want to create tables if they don't exist upon initialization
        # self.db_repository.create_tables_if_not_exist() # Assuming such a method exists in SQLiteRepository
        self.db_repository.initializeDB()

    def get_repository(self) -> SQLiteRepository | None:
        """
        Returns the initialized SQLiteRepository instance.
        """
        return self.db_repository

    # Add other methods here to interact with CryptoPaladin and SQLiteRepository
    # For example:
    # def add_password_entry(...):
    #     if not self.db_repository:
    #         raise Exception("Repository not initialized.")
    #     # ... encryption logic ...
    #     self.db_repository.create_password_entry(...)

    # def get_all_passwords_decrypted(...):
    #     if not self.db_repository:
    #         raise Exception("Repository not initialized.")
    #     encrypted_entries = self.db_repository.get_all_passwords()
    #     decrypted_entries = []
    #     for entry in encrypted_entries:
    #         # ... decryption logic using self.derived_key ...
    #         decrypted_entries.append(decrypted_entry)
    #     return decrypted_entries

    def add_password_entry_controller(self, service: str, username: str, email: str | None, password: str,
                                      link: str | None, category: str | None, note: str | None) -> None:
        """
        Adds a new password entry to the database via the repository.
        Assumes password is already encrypted.
        """
        if not self.db_repository:
            raise Exception("Database repository not initialized. Cannot add entry.")

        try:
            enc_nonce, enc_ciphertext, enc_tag = cp.encrypt(password.encode('utf-8'), self.derived_key)
            self.db_repository.create_password_entry(
                password_entity=Password(
                    service=service,
                    username=username,
                    email=email,
                    password=enc_ciphertext, # This is the encrypted password
                    nonce=enc_nonce,
                    tag=enc_tag,
                    link=link,
                    category=category,
                    note=note
                )
            )
            print(f"Controller: Successfully added entry for service '{service}' to the database.")
        except Exception as e:
            print(f"Controller: Error adding password entry for service '{service}': {e}")
            # Re-raise the exception to be handled by the UI if needed,
            # or handle it more gracefully here (e.g., logging).
            raise Exception(f"Failed to add password entry in controller: {e}")

    def get_passwords(self, page:int|None=None, size:int|None=None)->list[Password]:
        try:
            return self.db_repository.get_all_passwords()
        except Exception as ex:
            print(f"Exception occured while trying to retrieve password {str(ex)}")

    def backup_vault(self, backup_path:str|None = None):
        try:
            if not backup_path:
                # Value None
                kf = Path(self.key_file_path)
                if kf.is_file():
                    parent_dir = kf.parent
                    backup_path = parent_dir/"PaladinVault_Backup.bin"
                    
                
            self.db_repository.backup(backup_path=backup_path)
        except Exception as ex:
            raise Exception(f"Failed backing up the vault")

if __name__ == '__main__':
    # Example Usage (for testing purposes)
    controller = PaladinVaultController()

    # --- You NEED to create a dummy key file first using CryptoPaladin.generate_key and save_key ---
    # Example:
    # from Backend.CryptoUtils import CryptoPaladin as cp
    # password = "testpassword"
    # key, salt = cp.generate_key(password)
    # cp.save_key(key, salt, "dummy_key.bin") # Saves H(password||salt) and salt
    # print("Dummy key file created as dummy_key.bin")
    # --- ---

    DUMMY_KEY_FILE = r"D:\MyFiles\side_projects\PythonPassManager\testdir\dummy_key.bin"
    DUMMY_DB_FILE = r"D:\MyFiles\side_projects\PythonPassManager\testdir\dummy_Passwords.db"

    password = "test"
    generate_result = cp.generate_key(password)
    print("Key: ",generate_result[0])
    print("Salt: ",generate_result[1])

    cp.save_key(generate_result[0],generate_result[1],DUMMY_KEY_FILE)

    if not os.path.exists(DUMMY_KEY_FILE):
        print(f"Error: Dummy key file '{DUMMY_KEY_FILE}' not found.")
        print("Please create it first (see commented out code above).")
    else:
        try:
            print(f"Attempting login with password 'testpassword' and key file '{DUMMY_KEY_FILE}'...")
            if controller.login("test", DUMMY_KEY_FILE):
                print("Controller login successful.")

                # Initialize repository
                controller.initialize_repository()
                repo = controller.get_repository()
                if repo:
                    print(f"Repository ready for operations on {DUMMY_DB_FILE}.")
                    # Further operations e.g. repo.create_password_entry(...)
                else:
                    print("Failed to get repository.")
            else:
                # This case should ideally not be reached if exceptions are handled correctly
                print("Controller login failed (unexpected).")

        except KeyFileNotFoundException as e:
            print(f"Login Error: {e}")
        except InvalidPasswordException as e:
            print(f"Login Error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")