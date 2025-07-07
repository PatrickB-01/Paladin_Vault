import os
import sys

# Adjust import path for backend modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from Backend.CryptoUtils import CryptoPaladin as cp
from Backend.CryptoUtils.CryptoPaladinExceptions import InvalidPasswordException, KeyFileNotFoundException
from Backend.Repository.SQLiteRepository import SQLiteRepository

class PaladinVaultController:
    def __init__(self):
        self.derived_key = None
        self.db_repository = None

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
            if not cp.verify_key(input_password=master_password, key_hash_from_file=loaded_key_data, salt=salt):
                # This path should ideally be caught by verify_key raising InvalidPasswordException
                raise InvalidPasswordException("Master password verification failed.")

            # 3. If verification is successful, derive the actual encryption key for database operations
            # This derived key is what will be used for encrypting/decrypting data in the database.
            self.derived_key, _ = cp.derive_key(password=master_password, salt=salt, key_length=32) # Use the same salt

            # 4. (Optional but recommended) Initialize SQLiteRepository here if login is successful
            # self.initialize_repository() # You'll need to decide where your DB file is stored.

            print("Login successful. Encryption key derived.")
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


    def initialize_repository(self, db_path: str):
        """
        Initializes the SQLiteRepository with the derived key.
        This should be called after a successful login.
        """
        if not self.derived_key:
            raise Exception("Derived key is not available. Login must be successful first.")

        self.db_repository = SQLiteRepository(maindb_path=db_path, key=self.derived_key)
        print(f"Database repository initialized with path: {db_path}")
        # You might want to create tables if they don't exist upon initialization
        # self.db_repository.create_tables_if_not_exist() # Assuming such a method exists in SQLiteRepository

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

    DUMMY_KEY_FILE = "dummy_key.bin"
    DUMMY_DB_FILE = "dummy_test_vault.db"

    if not os.path.exists(DUMMY_KEY_FILE):
        print(f"Error: Dummy key file '{DUMMY_KEY_FILE}' not found.")
        print("Please create it first (see commented out code above).")
    else:
        try:
            print(f"Attempting login with password 'testpassword' and key file '{DUMMY_KEY_FILE}'...")
            if controller.login("testpassword", DUMMY_KEY_FILE):
                print("Controller login successful.")

                # Initialize repository
                controller.initialize_repository(db_path=DUMMY_DB_FILE)
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