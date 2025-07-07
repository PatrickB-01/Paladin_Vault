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
        ttk.Button(action_bar, text="Add New", command=self.open_add_password_dialog).pack(side="left", padx=(0,5))
        ttk.Button(action_bar, text="Backup Vault", command = self.backup_vault).pack(side="left") # Placeholder for backup

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

        #repository = self.controller.get_repository()
        derived_key = self.controller.derived_key # The key used for DB encryption

        # if not repository:
        #     messagebox.showerror("Error", "Database repository is not initialized.")
        #     return
        if not derived_key:
            messagebox.showerror("Error", "Encryption key is not available.")
            return

        try:
            encrypted_passwords = self.controller.get_passwords()
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

    def open_add_password_dialog(self):
        # Pass `self.root` as parent and `self.controller`
        dialog = AddPasswordDialog(self.root, self, self.controller)
        # The dialog's save_entry method will call self.load_and_display_passwords() on this instance (its parent)
        # if save is successful, because it's passed as self.parent.
        # No explicit wait_window needed if the dialog handles its lifecycle and calls back for refresh.

    def backup_vault(self):
        # backup vault and display status
        try:
            self.controller.backup_vault()
        except Exception as ex:
            print(f"Exception occured while backing up the vault: {str(ex)}")

def start_main_app(controller: PaladinVaultController):
    # This function will eventually initialize and show the main app window
    print("Login successful, starting main application...")
    root = tk.Tk()
    app = PaladinVaultUIApp(root, controller) # Pass controller
    root.mainloop()


class AddPasswordDialog(tk.Toplevel):
    def __init__(self, parent, list:PaladinVaultUIApp,controller: PaladinVaultController):
        super().__init__(parent)
        self.parent = parent
        self.list = list
        self.controller = controller
        self.transient(parent) # Dialog stays on top of the parent window
        self.title("Add New Password Entry")
        self.geometry("500x550") # Adjusted size
        self.resizable(False, False)
        self.grab_set() # Modal behavior

        self.service_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.email_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.link_var = tk.StringVar()
        self.category_var = tk.StringVar(value="general") # Default value
        # Note will use a Text widget, not a StringVar directly for multi-line and char count

        self.setup_dialog_ui()

    def setup_dialog_ui(self):
        main_frame = ttk.Frame(self, padding="15")
        main_frame.pack(fill="both", expand=True)

        # --- Input Fields ---
        # Service
        ttk.Label(main_frame, text="Service:").grid(row=0, column=0, sticky="w", pady=2)
        service_entry = ttk.Entry(main_frame, textvariable=self.service_var, width=40)
        service_entry.grid(row=0, column=1, columnspan=2, sticky="ew", pady=2)

        # Username
        ttk.Label(main_frame, text="Username:").grid(row=1, column=0, sticky="w", pady=2)
        username_entry = ttk.Entry(main_frame, textvariable=self.username_var, width=40)
        username_entry.grid(row=1, column=1, columnspan=2, sticky="ew", pady=2)

        # Email
        ttk.Label(main_frame, text="Email (optional):").grid(row=2, column=0, sticky="w", pady=2)
        email_entry = ttk.Entry(main_frame, textvariable=self.email_var, width=40)
        email_entry.grid(row=2, column=1, columnspan=2, sticky="ew", pady=2)

        # Password
        ttk.Label(main_frame, text="Password:").grid(row=3, column=0, sticky="w", pady=2)
        password_frame = ttk.Frame(main_frame)
        password_frame.grid(row=3, column=1, columnspan=2, sticky="ew", pady=2)

        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="•", width=30)
        self.password_entry.pack(side="left", expand=True, fill="x")

        self.show_password_var_dialog = tk.BooleanVar(value=False)
        # Placeholder for actual icon button for show/hide
        show_hide_button = ttk.Checkbutton(password_frame, text="👁", variable=self.show_password_var_dialog, command=self.toggle_password_visibility_dialog, style="Toolbutton")
        show_hide_button.pack(side="left", padx=(5,0))
        # Placeholder for generate password button
        generate_button = ttk.Button(password_frame, text="Generate", width=8, command=self.generate_password_action)
        generate_button.pack(side="left", padx=(5,0))


        # Link
        ttk.Label(main_frame, text="Link (optional):").grid(row=4, column=0, sticky="w", pady=2)
        link_entry = ttk.Entry(main_frame, textvariable=self.link_var, width=40)
        link_entry.grid(row=4, column=1, columnspan=2, sticky="ew", pady=2)

        # Category
        ttk.Label(main_frame, text="Category (optional):").grid(row=5, column=0, sticky="w", pady=2)
        # Could use ttk.Combobox if predefined categories are desired later
        category_entry = ttk.Entry(main_frame, textvariable=self.category_var, width=40)
        category_entry.grid(row=5, column=1, columnspan=2, sticky="ew", pady=2)

        # Note
        ttk.Label(main_frame, text="Note (optional, max 1000 chars):").grid(row=6, column=0, sticky="nw", pady=2)
        note_frame = ttk.Frame(main_frame) # Frame for text widget and scrollbar
        note_frame.grid(row=6, column=1, columnspan=2, sticky="ew", pady=2)

        self.note_text = tk.Text(note_frame, height=5, width=38, wrap="word") # width in chars, height in lines
        note_scrollbar = ttk.Scrollbar(note_frame, orient="vertical", command=self.note_text.yview)
        self.note_text.configure(yscrollcommand=note_scrollbar.set)
        self.note_text.pack(side="left", fill="both", expand=True)
        note_scrollbar.pack(side="right", fill="y")
        # Character counter (placeholder, logic to be added)
        self.note_char_count_var = tk.StringVar(value="0/1000")
        ttk.Label(main_frame, textvariable=self.note_char_count_var).grid(row=7, column=1, columnspan=2, sticky="e", pady=(0,5))
        self.note_text.bind("<KeyRelease>", self.update_note_char_count) # Bind to KeyRelease
        self.update_note_char_count() # Initial call to set counter

        # --- Action Buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=8, column=0, columnspan=3, pady=(10,0))

        save_button = ttk.Button(button_frame, text="Save", command=self.save_entry)
        save_button.pack(side="left", padx=5)
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.destroy)
        cancel_button.pack(side="left", padx=5)

        # Configure column weights for responsiveness of central column
        main_frame.columnconfigure(1, weight=1)

        # Set focus to the first entry field
        service_entry.focus_set()



    def toggle_password_visibility_dialog(self):
        if self.show_password_var_dialog.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")

    def save_entry(self):
        service = self.service_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get() # No strip, allow spaces if user insists
        email = self.email_var.get().strip()
        link = self.link_var.get().strip()
        category = self.category_var.get().strip() if self.category_var.get().strip() else "general"
        note = self.note_text.get("1.0", tk.END).strip()

        # Validation
        if not service:
            messagebox.showerror("Validation Error", "Service field cannot be empty.", parent=self)
            return
        if not username:
            messagebox.showerror("Validation Error", "Username field cannot be empty.", parent=self)
            return
        if not password:
            messagebox.showerror("Validation Error", "Password field cannot be empty.", parent=self)
            return

        if len(note) > 1000:
            messagebox.showerror("Validation Error", "Note cannot exceed 1000 characters.", parent=self)
            return

        try:
            derived_key = self.controller.derived_key
            if not derived_key:
                messagebox.showerror("Error", "Encryption key not available. Cannot save.", parent=self)
                return

            #enc_nonce, enc_ciphertext, enc_tag = cp.encrypt(password.encode('utf-8'), derived_key)

            # Call the controller method to add the entry
            self.controller.add_password_entry_controller(
                service=service,
                username=username,
                email=email,
                password=password,
                link=link,
                category=category,
                note=note
            )

            messagebox.showinfo("Success", "Password entry saved successfully!", parent=self.parent) # Show on parent
            self.list.load_and_display_passwords() # Refresh parent's list
            self.destroy() # Close dialog

        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save entry: {e}", parent=self)
            print(f"Error during save_entry: {e}")

    def generate_password_action(self):
        try:
            generated_password = cp.generate_secure_password(length=16) # Default length 16
            self.password_var.set(generated_password)

            # Briefly show the password
            self.password_entry.config(show="")
            self.show_password_var_dialog.set(True) # Sync checkbox state

            # Copy to clipboard
            try:
                import pyperclip
                pyperclip.copy(generated_password)
                # Optionally show a small notification label that it was copied
                # For now, just print to console
                print("Generated password copied to clipboard.")
            except ImportError:
                print("Pyperclip not installed. Cannot copy to clipboard. Please install it: pip install pyperclip")
            except Exception as clip_err:
                print(f"Error copying to clipboard: {clip_err}")

            # After a delay, re-mask the password
            self.after(2000, self.remask_password_after_generate) # 2 seconds

        except ValueError as ve:
            messagebox.showerror("Password Generation Error", str(ve), parent=self)
        except Exception as e:
            messagebox.showerror("Error", f"Could not generate password: {e}", parent=self)

    def remask_password_after_generate(self):
        # Only remask if the user hasn't unchecked the visibility toggle themselves during the delay
        if self.show_password_var_dialog.get():
            self.password_entry.config(show="•")
            self.show_password_var_dialog.set(False) # Sync checkbox state

    def update_note_char_count(self, event=None):
        MAX_NOTE_LEN = 1000
        current_text = self.note_text.get("1.0", tk.END).rstrip('\n') # rstrip to avoid counting trailing newline
        current_len = len(current_text)

        if current_len > MAX_NOTE_LEN:
            # Trim text if it exceeds max length
            self.note_text.delete(f"1.0 + {MAX_NOTE_LEN}c", tk.END)
            current_len = MAX_NOTE_LEN

        self.note_char_count_var.set(f"{current_len}/{MAX_NOTE_LEN}")



# Original LoadingWindow and other functions might be reused or refactored later if needed.
# For now, we are focusing on the Login Screen.

if __name__ == "__main__":
    # --- To set up test data, uncomment the line below and run this script ONCE ---
    # setup_test_environment() # You might want to specify a path e.g., setup_test_environment("./test_data")
    # --- Then, comment it out again to run the application normally ---

    root = tk.Tk()
    login_app = LoginWindow(root)
    root.mainloop()
