import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk  # Pillow for image handling
import os
import pathlib
import sys

# Adjust import path for backend modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from Backend.CryptoUtils import CryptoPaladin as cp
from Backend.CryptoUtils.CryptoPaladinExceptions import InvalidPasswordException, KeyFileNotFoundException
from PaladinVaultLogic.PaladinVaultController import PaladinVaultController


APP_NAME = "Paladin Vault"
KEY_FILE_NAME = "key.bin" # Default key file name to scan for

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Secure Login - {APP_NAME}")
        self.root.geometry("500x450") # Adjusted size for better layout
        self.root.resizable(False, False)

        self.master_password_var = tk.StringVar()
        self.key_file_path_var = tk.StringVar()
        self.usb_status_var = tk.StringVar(value="USB key not detected.")

        self.controller = PaladinVaultController() # Instantiate the controller

        self.setup_ui()
        self.update_login_button_status() # Initial check
        self.auto_scan_usb() # Start auto-scan

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill="both", expand=True)

        # 1. Header Area
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill="x", pady=(0, 20))

        try:
            # Construct path relative to this script's location
            script_dir = os.path.dirname(os.path.abspath(__file__))
            logo_path = os.path.join(script_dir, '..', '..', 'assets', 'logo.png')

            if os.path.exists(logo_path):
                logo_image = Image.open(logo_path)
                logo_image = logo_image.resize((40, 40), Image.LANCZOS)
                self.logo_photo = ImageTk.PhotoImage(logo_image)
                logo_label = ttk.Label(header_frame, image=self.logo_photo)
                logo_label.pack(side="left", padx=(0, 10))
            else:
                # Fallback if logo not found
                logo_label = ttk.Label(header_frame, text="[Logo]")
                logo_label.pack(side="left", padx=(0, 10))
                print(f"Warning: Logo not found at {logo_path}")

        except Exception as e:
            print(f"Error loading logo: {e}")
            logo_label = ttk.Label(header_frame, text="[Logo]") # Fallback
            logo_label.pack(side="left", padx=(0, 10))


        app_name_label = ttk.Label(header_frame, text=APP_NAME, font=("Arial", 16, "bold"))
        app_name_label.pack(side="left")

        self.usb_status_indicator = ttk.Label(header_frame, textvariable=self.usb_status_var, foreground="red")
        self.usb_status_indicator.pack(side="right")


        # 2. Main Authentication Form
        auth_frame = ttk.LabelFrame(main_frame, text="Authentication", padding="15")
        auth_frame.pack(fill="x")

        # Master Password
        ttk.Label(auth_frame, text="Enter your Master Password:").grid(row=0, column=0, sticky="w", pady=(0,5))

        password_entry_frame = ttk.Frame(auth_frame)
        password_entry_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0,10))

        self.password_entry = ttk.Entry(password_entry_frame, textvariable=self.master_password_var, show="•", width=40)
        self.password_entry.pack(side="left", expand=True, fill="x")
        self.password_entry.focus_set() # Autofocus
        self.master_password_var.trace_add("write", lambda *args: self.update_login_button_status())

        self.show_password_var = tk.BooleanVar(value=False)
        show_password_button = ttk.Checkbutton(password_entry_frame, text="👁", variable=self.show_password_var, command=self.toggle_password_visibility, style="Toolbutton")
        show_password_button.pack(side="left", padx=(5,0))


        # USB Key Detection
        ttk.Label(auth_frame, text="USB Key File:").grid(row=2, column=0, sticky="w", pady=(10,5))

        usb_key_frame = ttk.Frame(auth_frame)
        usb_key_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0,10))

        self.key_file_entry = ttk.Entry(usb_key_frame, textvariable=self.key_file_path_var, state="readonly", width=30)
        self.key_file_entry.pack(side="left", expand=True, fill="x")
        self.key_file_path_var.trace_add("write", lambda *args: self.update_login_button_status())

        browse_button = ttk.Button(usb_key_frame, text="Browse...", command=self.browse_for_key_file)
        browse_button.pack(side="left", padx=(5,0))


        # Login Button
        self.login_button = ttk.Button(main_frame, text="Unlock Vault", command=self.attempt_login, state="disabled")
        self.login_button.pack(pady=(20,0))

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")

    def auto_scan_usb(self):
        print("Auto-scanning for USB key...")
        try:
            found_path = cp.scan_usb_for_file(KEY_FILE_NAME)
            if found_path:
                self.key_file_path_var.set(str(found_path))
                self.usb_status_var.set(f"✅ USB Key detected: {os.path.basename(str(found_path))}")
                self.usb_status_indicator.config(foreground="green")
                print(f"Key found: {found_path}")
            else:
                # Keep existing manually selected path if any, otherwise clear
                if not self.key_file_path_var.get(): # Only update if not manually set
                    self.usb_status_var.set(f"❌ USB key '{KEY_FILE_NAME}' not found.")
                    self.usb_status_indicator.config(foreground="red")
                print(f"Key '{KEY_FILE_NAME}' not found via auto-scan.")
        except Exception as e:
            self.usb_status_var.set("⚠️ Error during USB scan.")
            self.usb_status_indicator.config(foreground="orange")
            print(f"Error during auto_scan_usb: {e}")

        self.update_login_button_status()
        # self.root.after(5000, self.auto_scan_usb) # Optional: Rescan periodically, might be annoying

    def browse_for_key_file(self):
        filepath = filedialog.askopenfilename(
            title="Select Key File",
            filetypes=(("Key files", f"*{KEY_FILE_NAME}"), ("All files", "*.*"))
        )
        if filepath:
            self.key_file_path_var.set(filepath)
            self.usb_status_var.set(f"✅ Key file selected: {os.path.basename(filepath)}")
            self.usb_status_indicator.config(foreground="green")
        self.update_login_button_status()


    def update_login_button_status(self, *args):
        password_filled = bool(self.master_password_var.get())
        key_file_selected = bool(self.key_file_path_var.get())

        if password_filled and key_file_selected:
            self.login_button.config(state="normal")
        else:
            self.login_button.config(state="disabled")

    def attempt_login(self):
        master_password = self.master_password_var.get()
        key_file = self.key_file_path_var.get()

        if not master_password:
            messagebox.showerror("Login Error", "Master Password cannot be empty.")
            return
        if not key_file:
            messagebox.showerror("Login Error", "USB Key file not selected.")
            return

        if not os.path.exists(key_file):
            messagebox.showerror("Login Error", f"Key file not found at: {key_file}")
            self.key_file_path_var.set("") # Clear invalid path
            self.usb_status_var.set(f"❌ USB key not found.")
            self.usb_status_indicator.config(foreground="red")
            self.update_login_button_status()
            return

        print(f"Attempting login with password: '{master_password[:2]}...' and key file: '{key_file}'")

        print(f"Attempting login with password: '{master_password[:2]}...' and key file: '{key_file}'")

        try:
            if self.controller.login(master_password, key_file):
                messagebox.showinfo("Login Success", "Vault Unlocked!")

                # --- Database Initialization ---
                # For now, let's assume a fixed DB name in the same dir as the key file
                # In a real app, this might be configurable or stored elsewhere.
                key_file_dir = os.path.dirname(key_file)
                db_name = "PaladinVault.db" # Or derive from key file name, e.g. os.path.splitext(os.path.basename(key_file))[0] + ".db"
                db_path = os.path.join(key_file_dir, db_name)

                print(f"Attempting to initialize database at: {db_path}")
                self.controller.initialize_repository(db_path)
                # --- End Database Initialization ---

                self.root.destroy() # Close login window
                start_main_app(self.controller) # Pass controller to main app
            # No 'else' needed as controller.login will raise exceptions on failure

        except InvalidPasswordException:
            messagebox.showerror("Login Failed", "Invalid Master Password.")
        except KeyFileNotFoundException: # Catching the specific exception from controller
            messagebox.showerror("Login Error", f"Key file not found: {key_file}")
            self.key_file_path_var.set("") # Clear invalid path
            self.usb_status_var.set(f"❌ USB key not found.")
            self.usb_status_indicator.config(foreground="red")
            self.update_login_button_status()
        except Exception as e:
            messagebox.showerror("Login Error", f"An unexpected error occurred: {e}")
            print(f"Login exception: {e}")


# Placeholder for the main application window (from original file, simplified)
class PaladinVaultUIApp:
    def __init__(self, root, controller: PaladinVaultController):
        self.root = root
        self.controller = controller # Store the controller instance
        self.root.title(f"{APP_NAME} - Main")
        self.root.geometry("800x600") # Increased height for table

        self.setup_main_ui()
        self.load_and_display_passwords()

        # Actual UI for password management will be built here or restored using self.controller

    def setup_main_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill="both", expand=True)

        # Placeholder for top bar actions (e.g., Add, Backup)
        action_bar = ttk.Frame(main_frame)
        action_bar.pack(fill="x", pady=(0,10))
        ttk.Button(action_bar, text="Add New").pack(side="left", padx=(0,5))
        ttk.Button(action_bar, text="Backup Vault").pack(side="left")

        # Password display area
        columns = ("service", "username", "password", "link", "note") # Added more columns
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings")

        self.tree.heading("service", text="Service")
        self.tree.heading("username", text="Username")
        self.tree.heading("password", text="Password") # Will show decrypted
        self.tree.heading("link", text="Link")
        self.tree.heading("note", text="Note")

        self.tree.column("service", width=150)
        self.tree.column("username", width=150)
        self.tree.column("password", width=150) # Adjust as needed
        self.tree.column("link", width=150)
        self.tree.column("note", width=200)

        # Add scrollbars
        vsb = ttk.Scrollbar(main_frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=vsb.set)

        hsb = ttk.Scrollbar(main_frame, orient="horizontal", command=self.tree.xview)
        hsb.pack(side='bottom', fill='x')
        self.tree.configure(xscrollcommand=hsb.set)

        self.tree.pack(fill="both", expand=True)

    def load_and_display_passwords(self):
        # Clear existing items from the tree
        for item in self.tree.get_children():
            self.tree.delete(item)

        repository = self.controller.get_repository()
        derived_key = self.controller.derived_key # The key used for DB encryption

        if not repository:
            messagebox.showerror("Error", "Database repository is not initialized.")
            return
        if not derived_key:
            messagebox.showerror("Error", "Encryption key is not available.")
            return

        try:
            encrypted_passwords = repository.get_all_passwords()
            if not encrypted_passwords:
                # Display a message in the tree or a label if no passwords
                # For now, just print to console. UI can be enhanced later.
                print("No passwords found in the vault.")
                # self.tree.insert("", "end", values=("","No passwords yet.","","",""))
                return

            for p_entity in encrypted_passwords:
                try:
                    # Decrypt password field
                    decrypted_password_bytes = cp.decrypt(
                        key=derived_key,
                        nonce=p_entity.nonce,
                        ciphertext=p_entity.password, # This is the encrypted password
                        tag=p_entity.tag
                    )
                    decrypted_password = decrypted_password_bytes.decode()

                    # Other fields are assumed to be stored unencrypted or handled similarly if encrypted
                    # For this example, service, username, link, note are directly used.
                    # If they were also encrypted, they'd need similar decryption steps.
                    self.tree.insert("", "end", values=(
                        p_entity.service,
                        p_entity.username,
                        decrypted_password, # Display decrypted password
                        p_entity.link,
                        p_entity.note
                    ))
                except Exception as decrypt_error:
                    print(f"Error decrypting password for service {p_entity.service}: {decrypt_error}")
                    # Display an error placeholder in the tree for this entry
                    self.tree.insert("", "end", values=(
                        p_entity.service,
                        p_entity.username,
                        "DECRYPTION ERROR",
                        p_entity.link,
                        p_entity.note
                    ))
        except Exception as e:
            messagebox.showerror("Load Error", f"Failed to load passwords: {e}")
            print(f"Error in load_and_display_passwords: {e}")


def start_main_app(controller: PaladinVaultController):
    # This function will eventually initialize and show the main app window
    print("Login successful, starting main application...")
    root = tk.Tk()
    app = PaladinVaultUIApp(root, controller) # Pass controller
    root.mainloop()

# --- Test Data Setup ---
def setup_test_environment(base_path="."):
    """
    Sets up a dummy key.bin and PaladinVault.db for testing.
    IMPORTANT: This will overwrite existing files with these names in the base_path.
    """
    TEST_MASTER_PASSWORD = "testpassword"
    KEY_FILE = os.path.join(base_path, "key.bin")
    DB_FILE = os.path.join(base_path, "PaladinVault.db")

    print(f"Setting up test environment in: {os.path.abspath(base_path)}")
    print(f"Test Master Password: {TEST_MASTER_PASSWORD}")

    # 1. Generate and Save Key File
    try:
        print(f"Generating key file at: {KEY_FILE}")
        key_hash, salt = cp.generate_key(TEST_MASTER_PASSWORD)
        cp.save_key(key_hash, salt, KEY_FILE)
        print("key.bin created successfully.")
    except Exception as e:
        print(f"Error creating key.bin: {e}")
        return

    # 2. Derive encryption key and setup database
    try:
        print(f"Setting up database at: {DB_FILE}")
        derived_key, _ = cp.derive_key(TEST_MASTER_PASSWORD, salt)

        # Ensure database is clean for test setup
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
            print(f"Removed existing DB_FILE: {DB_FILE}")

        repo = SQLiteRepository(maindb_path=DB_FILE, key=derived_key)
        # The SQLiteRepository constructor should ideally call a method to create tables if they don't exist.
        # Assuming it does, or that create_password_entry will handle table creation.
        # If not, you might need: repo.create_tables()

        print("Database repository initialized.")

        # 3. Add a test password entry
        test_service_password = "mysecretwebsite_password"
        nonce, ciphertext, tag = cp.encrypt(test_service_password.encode(), derived_key)
        
        repo.create_password_entry(
            service="TestService",
            username="testuser@example.com",
            password=ciphertext, # Storing the encrypted password
            nonce=nonce,
            tag=tag,
            link="https://example.com",
            note="This is a test entry."
        )
        print("Test password entry added to the database.")

        # Add another entry
        test_service_password_2 = "anotherSecurePa$$"
        nonce2, ciphertext2, tag2 = cp.encrypt(test_service_password_2.encode(), derived_key)
        repo.create_password_entry(
            service="AnotherWebApp",
            username="jane.doe",
            password=ciphertext2,
            nonce=nonce2,
            tag=tag2,
            link="https.another.com/login",
            note="Second test entry for variety."
        )
        print("Second test password entry added.")
        print("Test environment setup complete.")

    except Exception as e:
        print(f"Error setting up database or adding test entry: {e}")

# Original LoadingWindow and other functions might be reused or refactored later if needed.
# For now, we are focusing on the Login Screen.

if __name__ == "__main__":
    # --- To set up test data, uncomment the line below and run this script ONCE ---
    # setup_test_environment() # You might want to specify a path e.g., setup_test_environment("./test_data")
    # --- Then, comment it out again to run the application normally ---

    root = tk.Tk()
    login_app = LoginWindow(root)
    root.mainloop()
