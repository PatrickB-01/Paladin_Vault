import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from Backend.CryptoUtils import CryptoPaladin as cp
from Backend.api import create_app


class ApiSmokeTest(unittest.TestCase):
    API_PREFIX = "/api/v1"

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="paladin_smoke_")
        os.environ["LOCALAPPDATA"] = self.tmpdir

        self.key_file_path = os.path.join(self.tmpdir, "key.bin")
        key_hash, salt = cp.generate_key("test-master-password")
        cp.save_key(key_hash, salt, self.key_file_path)

        app = create_app()
        self.client = TestClient(app)

        login_res = self.client.post(
            f"{self.API_PREFIX}/auth/token",
            json={
                "master_password": "test-master-password",
                "key_file_path": self.key_file_path,
                "require_usb": False,
            },
        )
        self.assertEqual(login_res.status_code, 200, login_res.text)
        self.token = login_res.json()["access_token"]
        self.auth_header = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self):
        try:
            self.client.post(f"{self.API_PREFIX}/auth/logout", headers=self.auth_header)
        except Exception:
            pass

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_full_vault_smoke(self):
        create_res = self.client.post(
            f"{self.API_PREFIX}/vault/passwords",
            headers=self.auth_header,
            json={
                "service": "discord",
                "username": "paladin_user",
                "password": "secret-123",
                "email": "paladin@example.com",
                "link": "https://discord.com",
                "category": "social",
                "note": "smoke test",
            },
        )
        self.assertEqual(create_res.status_code, 200, create_res.text)
        created = create_res.json()
        self.assertEqual(created["service"], "discord")
        self.assertEqual(created["password"], "secret-123")
        pid = created["pid"]

        list_res = self.client.get(f"{self.API_PREFIX}/vault/passwords", headers=self.auth_header)
        self.assertEqual(list_res.status_code, 200, list_res.text)
        list_payload = list_res.json()
        self.assertIn("items", list_payload)
        self.assertIn("total", list_payload)
        self.assertGreaterEqual(len(list_payload["items"]), 1)
        self.assertGreaterEqual(list_payload["total"], 1)

        get_res = self.client.get(f"{self.API_PREFIX}/vault/passwords/{pid}", headers=self.auth_header)
        self.assertEqual(get_res.status_code, 200, get_res.text)
        self.assertEqual(get_res.json()["username"], "paladin_user")

        filtered_res = self.client.get(
            f"{self.API_PREFIX}/vault/passwords",
            params={"service": "disc"},
            headers=self.auth_header,
        )
        self.assertEqual(filtered_res.status_code, 200, filtered_res.text)
        filtered_payload = filtered_res.json()
        self.assertGreaterEqual(filtered_payload["total"], 1)
        self.assertGreaterEqual(len(filtered_payload["items"]), 1)

        # Backward compatibility route remains available but deprecated.
        legacy_search_res = self.client.get(
            f"{self.API_PREFIX}/vault/passwords/search", params={"service": "disc"}, headers=self.auth_header
        )
        self.assertEqual(legacy_search_res.status_code, 200, legacy_search_res.text)
        self.assertGreaterEqual(len(legacy_search_res.json()), 1)

        update_res = self.client.put(
            f"{self.API_PREFIX}/vault/passwords/{pid}",
            headers=self.auth_header,
            json={
                "service": "discord",
                "username": "paladin_user_updated",
                "password": "secret-456",
                "category": "social",
            },
        )
        self.assertEqual(update_res.status_code, 200, update_res.text)
        self.assertEqual(update_res.json()["username"], "paladin_user_updated")
        self.assertEqual(update_res.json()["password"], "secret-456")

        backup_path = os.path.join(self.tmpdir, "vault_backup.bin")
        backup_res = self.client.post(
            f"{self.API_PREFIX}/vault/backup",
            headers=self.auth_header,
            json={"backup_path": backup_path},
        )
        self.assertEqual(backup_res.status_code, 200, backup_res.text)
        self.assertTrue(Path(backup_path).exists())

        restore_res = self.client.post(
            f"{self.API_PREFIX}/vault/restore",
            headers=self.auth_header,
            json={"backup_path": backup_path},
        )
        self.assertEqual(restore_res.status_code, 200, restore_res.text)

        delete_res = self.client.delete(f"{self.API_PREFIX}/vault/passwords/{pid}", headers=self.auth_header)
        self.assertEqual(delete_res.status_code, 200, delete_res.text)

    def test_logout_invalidates_session(self):
        logout_res = self.client.post(f"{self.API_PREFIX}/auth/logout", headers=self.auth_header)
        self.assertEqual(logout_res.status_code, 200, logout_res.text)

        after_logout_res = self.client.get(f"{self.API_PREFIX}/vault/passwords", headers=self.auth_header)
        self.assertEqual(after_logout_res.status_code, 401, after_logout_res.text)

    def test_list_pagination_and_sorting(self):
        entries = [
            {"service": "github", "username": "c-user", "password": "p1", "category": "work"},
            {"service": "discord", "username": "a-user", "password": "p2", "category": "social"},
            {"service": "gmail", "username": "b-user", "password": "p3", "category": "personal"},
        ]

        for entry in entries:
            create_res = self.client.post(f"{self.API_PREFIX}/vault/passwords", headers=self.auth_header, json=entry)
            self.assertEqual(create_res.status_code, 200, create_res.text)

        page1_res = self.client.get(
            f"{self.API_PREFIX}/vault/passwords",
            headers=self.auth_header,
            params={"page": 1, "size": 2, "sort_by": "username", "sort_dir": "asc"},
        )
        self.assertEqual(page1_res.status_code, 200, page1_res.text)
        page1_payload = page1_res.json()
        self.assertEqual(page1_payload["page"], 1)
        self.assertEqual(page1_payload["size"], 2)
        self.assertGreaterEqual(page1_payload["total"], 3)
        page1 = page1_payload["items"]
        self.assertEqual(len(page1), 2)
        self.assertEqual(page1[0]["username"], "a-user")
        self.assertEqual(page1[1]["username"], "b-user")

        page2_res = self.client.get(
            f"{self.API_PREFIX}/vault/passwords",
            headers=self.auth_header,
            params={"page": 2, "size": 2, "sort_by": "username", "sort_dir": "asc"},
        )
        self.assertEqual(page2_res.status_code, 200, page2_res.text)
        page2 = page2_res.json()["items"]
        self.assertEqual(len(page2), 1)
        self.assertEqual(page2[0]["username"], "c-user")

    def test_list_filtering_by_category_and_service(self):
        entries = [
            {"service": "discord", "username": "social-1", "password": "p1", "category": "social"},
            {"service": "x-social", "username": "social-2", "password": "p2", "category": "social"},
            {"service": "github", "username": "work-1", "password": "p3", "category": "work"},
        ]

        for entry in entries:
            create_res = self.client.post(f"{self.API_PREFIX}/vault/passwords", headers=self.auth_header, json=entry)
            self.assertEqual(create_res.status_code, 200, create_res.text)

        category_res = self.client.get(
            f"{self.API_PREFIX}/vault/passwords",
            headers=self.auth_header,
            params={"category": "social", "sort_by": "service", "sort_dir": "asc"},
        )
        self.assertEqual(category_res.status_code, 200, category_res.text)
        category_payload = category_res.json()
        self.assertEqual(category_payload["total"], 2)
        self.assertEqual(len(category_payload["items"]), 2)
        self.assertTrue(all(item["category"] == "social" for item in category_payload["items"]))

        combined_res = self.client.get(
            f"{self.API_PREFIX}/vault/passwords",
            headers=self.auth_header,
            params={"service": "disc", "category": "social"},
        )
        self.assertEqual(combined_res.status_code, 200, combined_res.text)
        combined_payload = combined_res.json()
        self.assertEqual(combined_payload["total"], 1)
        self.assertEqual(len(combined_payload["items"]), 1)
        self.assertEqual(combined_payload["items"][0]["service"], "discord")

    def test_unversioned_compat_aliases(self):
        # Token route compatibility
        login_res = self.client.post(
            "/auth/token",
            json={
                "master_password": "test-master-password",
                "key_file_path": self.key_file_path,
                "require_usb": False,
            },
        )
        self.assertEqual(login_res.status_code, 200, login_res.text)
        compat_token = login_res.json()["access_token"]
        compat_header = {"Authorization": f"Bearer {compat_token}"}

        create_res = self.client.post(
            "/vault/passwords",
            headers=compat_header,
            json={"service": "compat", "username": "alias", "password": "alias-pass", "category": "test"},
        )
        self.assertEqual(create_res.status_code, 200, create_res.text)

        list_res = self.client.get("/vault/passwords", headers=compat_header)
        self.assertEqual(list_res.status_code, 200, list_res.text)
        self.assertGreaterEqual(list_res.json()["total"], 1)
        self.assertEqual(list_res.headers.get("Deprecation"), "true")
        self.assertIn("/api/v1", list_res.headers.get("Link", ""))

        logout_res = self.client.post("/auth/logout", headers=compat_header)
        self.assertEqual(logout_res.status_code, 200, logout_res.text)

    def test_versioned_routes_do_not_emit_deprecation_headers(self):
        res = self.client.get(f"{self.API_PREFIX}/health")
        self.assertEqual(res.status_code, 200, res.text)
        self.assertIsNone(res.headers.get("Deprecation"))

    def test_register_creates_vault_with_custom_db_path(self):
        new_key_path = os.path.join(self.tmpdir, "new-vault", "new-key.bin")
        new_db_path = os.path.join(self.tmpdir, "new-vault", "CustomVault.db")

        register_res = self.client.post(
            f"{self.API_PREFIX}/auth/register",
            json={
                "master_password": "new-master-password",
                "key_file_path": new_key_path,
                "db_path": new_db_path,
                "use_usb_key": False,
                "overwrite_existing": False,
            },
        )
        self.assertEqual(register_res.status_code, 200, register_res.text)
        register_payload = register_res.json()
        self.assertEqual(register_payload["db_path"], os.path.abspath(new_db_path))
        self.assertEqual(register_payload["key_file_path"], os.path.abspath(new_key_path))
        self.assertTrue(Path(new_key_path).exists())
        self.assertTrue(Path(new_db_path).exists())

        register_token = register_payload["access_token"]
        register_header = {"Authorization": f"Bearer {register_token}"}
        create_res = self.client.post(
            f"{self.API_PREFIX}/vault/passwords",
            headers=register_header,
            json={"service": "new", "username": "user", "password": "new-pass", "category": "test"},
        )
        self.assertEqual(create_res.status_code, 200, create_res.text)

        logout_res = self.client.post(f"{self.API_PREFIX}/auth/logout", headers=register_header)
        self.assertEqual(logout_res.status_code, 200, logout_res.text)

    def test_register_conflict_and_overwrite(self):
        key_path = os.path.join(self.tmpdir, "overwrite", "key.bin")
        db_path = os.path.join(self.tmpdir, "overwrite", "PaladinVault.db")

        first_res = self.client.post(
            f"{self.API_PREFIX}/auth/register",
            json={
                "master_password": "overwrite-master-password",
                "key_file_path": key_path,
                "db_path": db_path,
                "use_usb_key": False,
                "overwrite_existing": False,
            },
        )
        self.assertEqual(first_res.status_code, 200, first_res.text)
        first_token = first_res.json()["access_token"]

        logout_first_res = self.client.post(
            f"{self.API_PREFIX}/auth/logout",
            headers={"Authorization": f"Bearer {first_token}"},
        )
        self.assertEqual(logout_first_res.status_code, 200, logout_first_res.text)

        second_res = self.client.post(
            f"{self.API_PREFIX}/auth/register",
            json={
                "master_password": "overwrite-master-password",
                "key_file_path": key_path,
                "db_path": db_path,
                "use_usb_key": False,
                "overwrite_existing": False,
            },
        )
        self.assertEqual(second_res.status_code, 409, second_res.text)

        overwrite_res = self.client.post(
            f"{self.API_PREFIX}/auth/register",
            json={
                "master_password": "overwrite-master-password",
                "key_file_path": key_path,
                "db_path": db_path,
                "use_usb_key": False,
                "overwrite_existing": True,
            },
        )
        self.assertEqual(overwrite_res.status_code, 200, overwrite_res.text)


if __name__ == "__main__":
    unittest.main()
