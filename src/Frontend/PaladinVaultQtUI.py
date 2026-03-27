import os
import sys

import psutil
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from Backend.CryptoUtils import CryptoPaladin as cp
from Backend.CryptoUtils.CryptoPaladinExceptions import (
    InvalidPasswordException,
    InvalidUSBPathException,
    InvalidVaultConfigurationException,
    KeyFileNotFoundException,
    VaultAlreadyExistsException,
    VaultCreationException,
)
from PaladinVaultLogic.PaladinVaultController import PaladinVaultController


DISCORD_STYLE = """
QMainWindow { background-color: #313338; color: #dbdee1; }
QDialog { background-color: #232428; color: #dbdee1; }
QFrame#nav { background-color: #1e1f22; border: none; }
QFrame#listPane { background-color: #2b2d31; border: none; }
QFrame#detailPane { background-color: #232428; border: none; }
QLabel#title { font-size: 18px; font-weight: 700; color: #f2f3f5; }
QPushButton {
    background-color: #5865f2;
    color: white;
    border: none;
    border-radius: 8px;
    padding: 6px 12px;
}
QPushButton:hover { background-color: #4752c4; }
QLineEdit {
    background-color: #1e1f22;
    border: 1px solid #3f4147;
    border-radius: 6px;
    padding: 6px;
    color: #dbdee1;
}
QListWidget, QTableWidget {
    background-color: #2b2d31;
    border: 1px solid #3f4147;
    color: #dbdee1;
    gridline-color: #3f4147;
}
QHeaderView::section {
    background-color: #1e1f22;
    color: #dbdee1;
    border: 0;
    padding: 6px;
}
QToolBar {
    background: #232428;
    border-bottom: 1px solid #3f4147;
    spacing: 8px;
}
"""


def _find_usb_key(filename: str = "key.bin") -> str | None:
    for part in psutil.disk_partitions(all=False):
        if os.name == "nt":
            if "removable" not in part.opts.lower():
                continue
        else:
            if not (part.mountpoint.startswith("/media") or part.mountpoint.startswith("/run/media")):
                continue

        candidate = os.path.join(part.mountpoint, filename)
        if os.path.isfile(candidate):
            return candidate
    return None


def _is_path_on_removable(path: str) -> bool:
    abs_path = os.path.abspath(path)
    for part in psutil.disk_partitions(all=False):
        if os.name == "nt" and "removable" in part.opts.lower():
            mount = os.path.abspath(part.mountpoint)
            if abs_path.lower().startswith(mount.lower()):
                return True
        elif os.name != "nt" and (part.mountpoint.startswith("/media") or part.mountpoint.startswith("/run/media")):
            mount = os.path.abspath(part.mountpoint)
            if abs_path.startswith(mount):
                return True
    return False


class EntryDialog(QDialog):
    def __init__(self, title: str, initial_data: dict | None = None):
        super().__init__()
        self.setWindowTitle(title)
        self.setFixedSize(520, 440)
        self.setStyleSheet(DISCORD_STYLE)
        self.result_data: dict | None = None
        self._build_ui(initial_data or {})

    def _build_ui(self, data: dict):
        root = QVBoxLayout(self)

        form = QFormLayout()
        self.service_input = QLineEdit(data.get("service", ""))
        self.username_input = QLineEdit(data.get("username", ""))
        self.email_input = QLineEdit(data.get("email", ""))
        self.password_input = QLineEdit(data.get("password", ""))
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.link_input = QLineEdit(data.get("link", ""))
        self.category_input = QLineEdit(data.get("category", "general"))
        self.note_input = QLineEdit(data.get("note", ""))

        generate_btn = QPushButton("Generate Password")
        generate_btn.clicked.connect(self.generate_password)

        form.addRow("Service", self.service_input)
        form.addRow("Username", self.username_input)
        form.addRow("Email", self.email_input)
        form.addRow("Password", self.password_input)
        form.addRow("", generate_btn)
        form.addRow("Link", self.link_input)
        form.addRow("Category", self.category_input)
        form.addRow("Note", self.note_input)

        root.addLayout(form)

        actions = QHBoxLayout()
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        actions.addStretch(1)
        actions.addWidget(save_btn)
        actions.addWidget(cancel_btn)
        root.addLayout(actions)

    def generate_password(self):
        self.password_input.setText(cp.generate_secure_password(16))

    def save(self):
        service = self.service_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not service or not username or not password:
            QMessageBox.warning(self, "Validation", "Service, username, and password are required.")
            return

        self.result_data = {
            "service": service,
            "username": username,
            "email": self.email_input.text().strip() or None,
            "password": password,
            "link": self.link_input.text().strip() or None,
            "category": self.category_input.text().strip() or "general",
            "note": self.note_input.text().strip() or None,
        }
        self.accept()


class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.controller = PaladinVaultController()
        self.setWindowTitle("Paladin Vault Login")
        self.setFixedSize(520, 330)
        self.setStyleSheet(DISCORD_STYLE)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        title = QLabel("Unlock Paladin Vault")
        title.setObjectName("title")
        layout.addWidget(title)

        form = QFormLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Master password")

        key_file_row = QHBoxLayout()
        self.key_file_input = QLineEdit()
        self.key_file_input.setPlaceholderText("Path to key.bin")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.select_key_file)
        key_file_row.addWidget(self.key_file_input)
        key_file_row.addWidget(browse_btn)

        db_file_row = QHBoxLayout()
        self.db_file_input = QLineEdit()
        self.db_file_input.setPlaceholderText("Optional custom DB path (PaladinVault.db)")
        db_browse_btn = QPushButton("Browse")
        db_browse_btn.clicked.connect(self.select_db_file)
        db_file_row.addWidget(self.db_file_input)
        db_file_row.addWidget(db_browse_btn)

        self.usb_required = QCheckBox("Require USB key for authentication")
        self.usb_required.setChecked(False)

        scan_btn = QPushButton("Auto-detect USB key")
        scan_btn.clicked.connect(self.scan_usb_key)

        form.addRow("Master Password", self.password_input)
        form.addRow("Key File", key_file_row)
        form.addRow("Database File", db_file_row)
        form.addRow("Authentication", self.usb_required)
        form.addRow("USB Scan", scan_btn)

        layout.addLayout(form)

        actions = QHBoxLayout()
        unlock_btn = QPushButton("Unlock")
        unlock_btn.clicked.connect(self.login)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        actions.addStretch(1)
        actions.addWidget(unlock_btn)
        actions.addWidget(cancel_btn)

        layout.addLayout(actions)

    def select_key_file(self):
        selected, _ = QFileDialog.getOpenFileName(self, "Select Key File", "", "All Files (*)")
        if selected:
            self.key_file_input.setText(selected)

    def select_db_file(self):
        selected, _ = QFileDialog.getOpenFileName(
            self,
            "Select Database File",
            "",
            "SQLite DB (*.db);;All Files (*)",
        )
        if selected:
            self.db_file_input.setText(selected)

    def scan_usb_key(self):
        found = _find_usb_key("key.bin")
        if found:
            self.key_file_input.setText(found)
            QMessageBox.information(self, "USB Detected", f"Detected key file at:\n{found}")
        else:
            QMessageBox.warning(self, "USB Scan", "No USB key file named key.bin was found.")

    def login(self):
        master_password = self.password_input.text().strip()
        key_path = self.key_file_input.text().strip()
        db_path = self.db_file_input.text().strip() or None

        if not master_password:
            QMessageBox.warning(self, "Login", "Master password is required.")
            return

        if not key_path:
            QMessageBox.warning(self, "Login", "Key file path is required.")
            return

        if self.usb_required.isChecked() and not _is_path_on_removable(key_path):
            QMessageBox.warning(self, "Login", "Mandatory USB mode requires key file from removable drive.")
            return

        try:
            self.controller.login(master_password, key_path, db_path=db_path)
            self.accept()
        except InvalidPasswordException:
            QMessageBox.critical(self, "Login Failed", "Invalid master password.")
        except KeyFileNotFoundException:
            QMessageBox.critical(self, "Login Failed", "Key file not found.")
        except Exception as ex:
            QMessageBox.critical(self, "Login Failed", str(ex))


class PreLoginChoiceDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.choice: str | None = None
        self.setWindowTitle("Paladin Vault")
        self.setFixedSize(460, 220)
        self.setStyleSheet(DISCORD_STYLE)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        title = QLabel("Welcome to Paladin Vault")
        title.setObjectName("title")
        layout.addWidget(title)

        subtitle = QLabel("Choose an action before continuing")
        layout.addWidget(subtitle)

        buttons = QHBoxLayout()
        login_btn = QPushButton("Login to Existing Vault")
        login_btn.clicked.connect(self._choose_login)
        create_btn = QPushButton("Create New Vault")
        create_btn.clicked.connect(self._choose_create)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)

        buttons.addWidget(login_btn)
        buttons.addWidget(create_btn)
        buttons.addWidget(cancel_btn)
        layout.addLayout(buttons)

    def _choose_login(self):
        self.choice = "login"
        self.accept()

    def _choose_create(self):
        self.choice = "create"
        self.accept()


class CreateVaultDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.controller = PaladinVaultController()
        self.setWindowTitle("Create New Vault")
        self.setFixedSize(560, 360)
        self.setStyleSheet(DISCORD_STYLE)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        title = QLabel("Create New Vault")
        title.setObjectName("title")
        layout.addWidget(title)

        form = QFormLayout()

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Master password (min 8 chars)")

        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_input.setPlaceholderText("Confirm master password")

        key_file_row = QHBoxLayout()
        self.key_file_input = QLineEdit()
        self.key_file_input.setPlaceholderText("Path to new key.bin")
        browse_key_btn = QPushButton("Browse")
        browse_key_btn.clicked.connect(self.select_key_file)
        key_file_row.addWidget(self.key_file_input)
        key_file_row.addWidget(browse_key_btn)

        db_file_row = QHBoxLayout()
        self.db_file_input = QLineEdit()
        self.db_file_input.setPlaceholderText("Path to new PaladinVault.db")
        browse_db_btn = QPushButton("Browse")
        browse_db_btn.clicked.connect(self.select_db_file)
        db_file_row.addWidget(self.db_file_input)
        db_file_row.addWidget(browse_db_btn)

        self.use_usb_checkbox = QCheckBox("Store key file on USB/removable media")
        self.use_usb_checkbox.setChecked(False)

        form.addRow("Master Password", self.password_input)
        form.addRow("Confirm Password", self.confirm_password_input)
        form.addRow("Key File", key_file_row)
        form.addRow("Database File", db_file_row)
        form.addRow("USB Key", self.use_usb_checkbox)

        layout.addLayout(form)

        actions = QHBoxLayout()
        create_btn = QPushButton("Create Vault")
        create_btn.clicked.connect(self.create_vault)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        actions.addStretch(1)
        actions.addWidget(create_btn)
        actions.addWidget(cancel_btn)
        layout.addLayout(actions)

    def select_key_file(self):
        selected, _ = QFileDialog.getSaveFileName(
            self,
            "Select Key File",
            "key.bin",
            "All Files (*)",
            options=QFileDialog.Option.DontConfirmOverwrite,
        )
        if selected:
            self.key_file_input.setText(selected)

    def select_db_file(self):
        selected, _ = QFileDialog.getSaveFileName(
            self,
            "Select Database File",
            "PaladinVault.db",
            "SQLite DB (*.db)",
            options=QFileDialog.Option.DontConfirmOverwrite,
        )
        if selected:
            self.db_file_input.setText(selected)

    def create_vault(self):
        master_password = self.password_input.text().strip()
        confirm_password = self.confirm_password_input.text().strip()
        key_path = self.key_file_input.text().strip()
        db_path = self.db_file_input.text().strip() or None
        use_usb = self.use_usb_checkbox.isChecked()

        if not master_password:
            QMessageBox.warning(self, "Create Vault", "Master password is required.")
            return

        if master_password != confirm_password:
            QMessageBox.warning(self, "Create Vault", "Master password confirmation does not match.")
            return

        if not key_path:
            QMessageBox.warning(self, "Create Vault", "Key file path is required.")
            return

        if not db_path:
            QMessageBox.warning(self, "Create Vault", "Database path is required.")
            return

        try:
            self.controller.create_new_vault(
                master_password=master_password,
                key_file_path=key_path,
                db_path=db_path,
                use_usb_key=use_usb,
                overwrite_existing=False,
            )
            self.accept()
        except VaultAlreadyExistsException as ex:
            overwrite = QMessageBox.question(
                self,
                "Overwrite Existing Vault",
                f"{str(ex)}\n\nDo you want to overwrite existing files?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if overwrite != QMessageBox.StandardButton.Yes:
                return
            try:
                self.controller.create_new_vault(
                    master_password=master_password,
                    key_file_path=key_path,
                    db_path=db_path,
                    use_usb_key=use_usb,
                    overwrite_existing=True,
                )
                self.accept()
            except Exception as retry_ex:
                QMessageBox.critical(self, "Create Vault Failed", str(retry_ex))
        except InvalidUSBPathException:
            QMessageBox.critical(
                self,
                "Create Vault Failed",
                "USB key mode is enabled, but key path is not on removable media.",
            )
        except (InvalidPasswordException, InvalidVaultConfigurationException, VaultCreationException) as ex:
            QMessageBox.critical(self, "Create Vault Failed", str(ex))
        except Exception as ex:
            QMessageBox.critical(self, "Create Vault Failed", str(ex))


class PaladinVaultQtWindow(QMainWindow):
    def __init__(self, controller: PaladinVaultController):
        super().__init__()
        self.controller = controller
        self.selected_pid: int | None = None
        self.setWindowTitle("Paladin Vault")
        self.resize(1300, 820)
        self.setStyleSheet(DISCORD_STYLE)
        self._build_ui()

    def _build_ui(self):
        toolbar = QToolBar("Vault Actions")
        self.addToolBar(toolbar)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search services...")
        self.search_input.returnPressed.connect(self.search_passwords)
        toolbar.addWidget(self.search_input)

        add_action = QAction("Add", self)
        add_action.setShortcut(QKeySequence("Ctrl+N"))
        add_action.triggered.connect(self.open_add_dialog)
        toolbar.addAction(add_action)

        edit_action = QAction("Edit", self)
        edit_action.setShortcut(QKeySequence("Ctrl+E"))
        edit_action.triggered.connect(self.open_edit_dialog)
        toolbar.addAction(edit_action)

        delete_action = QAction("Delete", self)
        delete_action.setShortcut(QKeySequence(Qt.Key.Key_Delete))
        delete_action.triggered.connect(self.delete_selected)
        toolbar.addAction(delete_action)

        backup_action = QAction("Backup", self)
        backup_action.setShortcut(QKeySequence("Ctrl+B"))
        backup_action.triggered.connect(self.backup_vault)
        toolbar.addAction(backup_action)

        restore_action = QAction("Restore", self)
        restore_action.setShortcut(QKeySequence("Ctrl+R"))
        restore_action.triggered.connect(self.restore_vault)
        toolbar.addAction(restore_action)

        refresh_action = QAction("Refresh", self)
        refresh_action.setShortcut(QKeySequence(Qt.Key.Key_F5))
        refresh_action.triggered.connect(self.load_passwords)
        toolbar.addAction(refresh_action)

        focus_search_action = QAction("Focus Search", self)
        focus_search_action.setShortcut(QKeySequence("Ctrl+F"))
        focus_search_action.triggered.connect(self.search_input.setFocus)
        self.addAction(focus_search_action)

        copy_action = QAction("Copy Password", self)
        copy_action.setShortcut(QKeySequence("Ctrl+C"))
        copy_action.triggered.connect(self.copy_password)
        self.addAction(copy_action)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        nav_frame = QFrame()
        nav_frame.setObjectName("nav")
        nav_layout = QVBoxLayout(nav_frame)
        nav_layout.addWidget(self._title_label("Vault"))
        self.category_list = QListWidget()
        self.category_list.addItems(["All", "General", "Finance", "Social", "Work", "Custom"])
        self.category_list.currentTextChanged.connect(self.filter_by_category)
        nav_layout.addWidget(self.category_list)

        list_frame = QFrame()
        list_frame.setObjectName("listPane")
        list_layout = QVBoxLayout(list_frame)
        list_layout.addWidget(self._title_label("Entries"))
        self.password_table = QTableWidget(0, 4)
        self.password_table.setHorizontalHeaderLabels(["ID", "Service", "Username", "Category"])
        self.password_table.itemSelectionChanged.connect(self.populate_details)
        list_layout.addWidget(self.password_table)

        detail_frame = QFrame()
        detail_frame.setObjectName("detailPane")
        detail_layout = QVBoxLayout(detail_frame)
        detail_layout.addWidget(self._title_label("Details"))

        form_container = QWidget()
        form_layout = QFormLayout(form_container)
        self.detail_service = QLineEdit()
        self.detail_username = QLineEdit()
        self.detail_email = QLineEdit()
        self.detail_link = QLineEdit()
        self.detail_category = QLineEdit()
        self.detail_note = QLineEdit()
        self.detail_password = QLineEdit()
        self.detail_password.setEchoMode(QLineEdit.EchoMode.Password)

        form_layout.addRow("Service", self.detail_service)
        form_layout.addRow("Username", self.detail_username)
        form_layout.addRow("Email", self.detail_email)
        form_layout.addRow("Link", self.detail_link)
        form_layout.addRow("Category", self.detail_category)
        form_layout.addRow("Note", self.detail_note)
        form_layout.addRow("Password", self.detail_password)

        detail_buttons = QHBoxLayout()
        save_btn = QPushButton("Save Changes")
        save_btn.clicked.connect(self.save_details_changes)
        copy_btn = QPushButton("Copy Password")
        copy_btn.clicked.connect(self.copy_password)
        detail_buttons.addWidget(save_btn)
        detail_buttons.addWidget(copy_btn)

        detail_layout.addWidget(form_container)
        detail_layout.addLayout(detail_buttons)

        splitter.addWidget(nav_frame)
        splitter.addWidget(list_frame)
        splitter.addWidget(detail_frame)
        splitter.setSizes([240, 620, 440])

        container = QWidget()
        root_layout = QHBoxLayout(container)
        root_layout.addWidget(splitter)
        self.setCentralWidget(container)

        self.load_passwords()

    def _title_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("title")
        return label

    def _get_selected_pid(self) -> int | None:
        current = self.password_table.currentRow()
        if current < 0:
            return None
        pid_item = self.password_table.item(current, 0)
        if not pid_item:
            return None
        return int(pid_item.text())

    def _set_table_entries(self, entries):
        self.password_table.setRowCount(0)
        for item in entries:
            row = self.password_table.rowCount()
            self.password_table.insertRow(row)
            self.password_table.setItem(row, 0, QTableWidgetItem(str(item.pid)))
            self.password_table.setItem(row, 1, QTableWidgetItem(item.service))
            self.password_table.setItem(row, 2, QTableWidgetItem(item.username))
            self.password_table.setItem(row, 3, QTableWidgetItem(item.category or "general"))

    def load_passwords(self):
        self._set_table_entries(self.controller.get_passwords())

    def search_passwords(self):
        term = self.search_input.text().strip()
        if not term:
            self.load_passwords()
            return
        self._set_table_entries(self.controller.get_passwords_by_service(term))

    def filter_by_category(self, category: str):
        entries = self.controller.get_passwords()
        if not category or category == "All":
            self._set_table_entries(entries)
            return

        selected = [e for e in entries if (e.category or "general").lower() == category.lower()]
        self._set_table_entries(selected)

    def populate_details(self):
        pid = self._get_selected_pid()
        if pid is None:
            self.selected_pid = None
            return

        entry = self.controller.get_password_by_id(pid)
        if not entry:
            self.selected_pid = None
            return

        self.selected_pid = pid
        self.detail_service.setText(entry.service)
        self.detail_username.setText(entry.username)
        self.detail_email.setText(entry.email or "")
        self.detail_link.setText(entry.link or "")
        self.detail_category.setText(entry.category or "")
        self.detail_note.setText(entry.note or "")
        self.detail_password.setText(self.controller.decrypt_password(entry))

    def open_add_dialog(self):
        dialog = EntryDialog("Add Password Entry")
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.result_data:
            self.controller.add_password_entry_controller(**dialog.result_data)
            self.load_passwords()

    def open_edit_dialog(self):
        pid = self._get_selected_pid()
        if pid is None:
            QMessageBox.information(self, "Edit", "Select an entry first.")
            return

        entry = self.controller.get_password_by_id(pid)
        if not entry:
            QMessageBox.warning(self, "Edit", "Selected entry no longer exists.")
            self.load_passwords()
            return

        dialog = EntryDialog(
            "Edit Password Entry",
            {
                "service": entry.service,
                "username": entry.username,
                "email": entry.email,
                "password": self.controller.decrypt_password(entry),
                "link": entry.link,
                "category": entry.category,
                "note": entry.note,
            },
        )
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.result_data:
            self.controller.update_password_entry_controller(pid=pid, **dialog.result_data)
            self.load_passwords()

    def save_details_changes(self):
        if self.selected_pid is None:
            QMessageBox.information(self, "Save", "Select an entry first.")
            return

        self.controller.update_password_entry_controller(
            pid=self.selected_pid,
            service=self.detail_service.text().strip(),
            username=self.detail_username.text().strip(),
            email=self.detail_email.text().strip() or None,
            password=self.detail_password.text(),
            link=self.detail_link.text().strip() or None,
            category=self.detail_category.text().strip() or None,
            note=self.detail_note.text().strip() or None,
        )
        QMessageBox.information(self, "Save", "Entry updated.")
        self.load_passwords()

    def delete_selected(self):
        pid = self._get_selected_pid()
        if pid is None:
            QMessageBox.information(self, "Delete", "Select an entry first.")
            return

        confirm = QMessageBox.question(
            self,
            "Delete Entry",
            "Are you sure you want to delete this password entry?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        deleted = self.controller.delete_password_entry_controller(pid)
        if deleted:
            QMessageBox.information(self, "Delete", "Entry deleted.")
            self.load_passwords()
        else:
            QMessageBox.warning(self, "Delete", "Entry not found.")

    def backup_vault(self):
        backup_path, _ = QFileDialog.getSaveFileName(self, "Create Backup", "PaladinVault_Backup.bin", "Backup (*.bin)")
        if not backup_path:
            return

        try:
            self.controller.backup_vault(backup_path)
            QMessageBox.information(self, "Backup", f"Backup saved to:\n{backup_path}")
        except Exception as ex:
            QMessageBox.critical(self, "Backup", f"Backup failed: {str(ex)}")

    def restore_vault(self):
        backup_path, _ = QFileDialog.getOpenFileName(self, "Restore Backup", "", "Backup (*.bin);;All Files (*)")
        if not backup_path:
            return

        try:
            self.controller.restore_vault(backup_path)
            self.load_passwords()
            QMessageBox.information(self, "Restore", "Backup restored successfully.")
        except Exception as ex:
            QMessageBox.critical(self, "Restore", f"Restore failed: {str(ex)}")

    def copy_password(self):
        if not self.detail_password.text():
            QMessageBox.information(self, "Copy", "No password available to copy.")
            return

        QApplication.clipboard().setText(self.detail_password.text())
        QMessageBox.information(self, "Copy", "Password copied to clipboard.")

    def closeEvent(self, event):
        self.controller.logout()
        super().closeEvent(event)


def start_qt_ui():
    app = QApplication.instance() or QApplication(sys.argv)
    choice_dialog = PreLoginChoiceDialog()
    if choice_dialog.exec() != QDialog.DialogCode.Accepted:
        return

    dialog: LoginDialog | CreateVaultDialog
    if choice_dialog.choice == "create":
        dialog = CreateVaultDialog()
    else:
        dialog = LoginDialog()

    if dialog.exec() == QDialog.DialogCode.Accepted:
        window = PaladinVaultQtWindow(dialog.controller)
        window.show()
        app.exec()
