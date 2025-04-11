import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
import os
import platform
import time
import threading

# Simulate USB and password verification
def verify_usb_and_password(master_password):
    time.sleep(2)  # Simulated delay for USB check
    usb_connected = True  # Replace with real detection
    password_correct = master_password == "secret"  # Replace with real check
    return usb_connected and password_correct

# Check USB (replace with real logic)
def usb_has_key_file():
    return True

# Sample data
passwords = [
    {"email": "john@example.com", "service": "Gmail", "username": "john123"},
    {"email": "jane@work.com", "service": "Slack", "username": "jane_dev"},
    {"email": "admin@site.com", "service": "GitHub", "username": "admin42"},
]

class PaladinVaultUIApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Paladin Vault")
        self.root.geometry("800x500")
        self.setup_ui()

    def setup_ui(self):
        # top bar
        topbar = tk.Frame(self.root)
        topbar.pack(side="top",fill="x")

        tk.Label(topbar, text="Options", fg="white", bg="#2e3f4f", pady=10).grid(padx=10, pady=2,row=0,column=0)
        tk.Button(topbar, text="Backup", bg="#3a4b5c", fg="white", relief="flat").grid(padx=10, pady=2,row=0,column=1)


        # Left sidebar
        sidebar = tk.Frame(self.root, bg="#2e3f4f", width=150)
        sidebar.pack(side="left", fill="y")

        tk.Label(sidebar, text="Categories", fg="white", bg="#2e3f4f", pady=10).pack()

        categories = ["All", "Email", "Social", "Work", "Banking"]
        for cat in categories:
            tk.Button(sidebar, text=cat, bg="#3a4b5c", fg="white", relief="flat").pack(fill="x", padx=10, pady=2)

        # Main table area
        main_area = tk.Frame(self.root)
        main_area.pack(side="right", fill="both", expand=True)

        columns = ("email", "service", "username")
        self.tree = ttk.Treeview(main_area, columns=columns, show="headings")
        self.tree.heading("email", text="Email")
        self.tree.heading("service", text="Service")
        self.tree.heading("username", text="Username")

        for entry in passwords:
            self.tree.insert("", "end", values=(entry["email"], entry["service"], entry["username"]))

        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

def start_main_app():
    root = tk.Tk()
    app = PaladinVaultUIApp(root)
    root.mainloop()

def ask_for_master_password():
    master = tk.Tk()
    master.withdraw()

    password = simpledialog.askstring("Master Password", "Enter your master password:", show='*')
    if not password:
        messagebox.showerror("Error", "No password entered.")
        return
    master.destroy()
    def verify_and_start():
        if verify_usb_and_password(password):
            loading = LoadingWindow()
            #start_main_app()
        else:
            messagebox.showerror("Access Denied", "USB not found or password incorrect.")

    threading.Thread(target=verify_and_start).start()

class LoadingWindow():
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Scanning for USB Key...")
        self.root.geometry("300x120")
        self.root.resizable(False, False)
        
        tk.Label(self.root, text="Scanning for USB key...", font=("Arial", 12)).pack(pady=10)
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", padx=20, pady=10)
        self.progress.start(10)

        self.root.after(5000, self.check_usb)
        self.root.mainloop()

    def check_usb(self):
       
        if 1==1:
            self.root.destroy()
            messagebox.showinfo(title="Message",message="XXXXXXXXX")
            start_main_app()
        else:
            messagebox.showerror("USB Error", "Key not found.")


if __name__ == "__main__":
    loading = LoadingWindow()
    #ask_for_master_password()
