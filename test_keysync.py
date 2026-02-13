import importlib
import os
import tempfile
import unittest


class KeySyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.db")
        os.environ["CHAT_DB_PATH"] = self.db_path
        if "CHAT_JWT_SECRET" in os.environ:
            del os.environ["CHAT_JWT_SECRET"]
        if "VERCEL" in os.environ:
            del os.environ["VERCEL"]
        if "VERCEL_ENV" in os.environ:
            del os.environ["VERCEL_ENV"]
        import main

        importlib.reload(main)
        self.main = main

        from fastapi.testclient import TestClient

        self._tc = TestClient(main.app)
        self.client = self._tc.__enter__()

    def tearDown(self) -> None:
        try:
            self._tc.__exit__(None, None, None)
        except Exception:
            pass
        try:
            self.tmp.cleanup()
        except Exception:
            pass

    def _register_and_login(self, username: str, password: str) -> str:
        r = self.client.post("/api/auth/register", json={"username": username, "password": password})
        self.assertIn(r.status_code, (200, 409))
        r2 = self.client.post("/api/auth/login", json={"username": username, "password": password})
        self.assertEqual(r2.status_code, 200)
        return r2.json()["token"]

    def test_user_keys_roundtrip_and_conflict(self) -> None:
        token = self._register_and_login("alice", "password-password")
        h = {"authorization": f"Bearer {token}"}

        g0 = self.client.get("/api/me/keys", headers=h)
        self.assertEqual(g0.status_code, 404)

        payload = {
            "key_version": 1,
            "ecdh_p256_spki_b64": "A" * 40,
            "ecdsa_p256_spki_b64": "B" * 40,
            "ecdh_p256_pkcs8_b64": "C" * 80,
            "ecdsa_p256_pkcs8_b64": "D" * 80,
        }
        p = self.client.post("/api/me/keys", headers=h, json=payload)
        self.assertEqual(p.status_code, 200)

        g1 = self.client.get("/api/me/keys", headers=h)
        self.assertEqual(g1.status_code, 200)
        body = g1.json()
        self.assertEqual(body["public_keys"]["ecdh_p256_spki_b64"], payload["ecdh_p256_spki_b64"])
        self.assertEqual(body["private_keys"]["ecdh_p256_pkcs8_b64"], payload["ecdh_p256_pkcs8_b64"])

        conflict = dict(payload)
        conflict["ecdh_p256_spki_b64"] = "Z" * 40
        p2 = self.client.post("/api/me/keys", headers=h, json=conflict)
        self.assertEqual(p2.status_code, 409)

    def test_master_can_fetch_user_keys(self) -> None:
        token = self._register_and_login("bob", "password-password")
        h = {"authorization": f"Bearer {token}"}

        me = self.client.get("/api/me", headers=h).json()
        user_id = me["id"]

        payload = {
            "key_version": 1,
            "ecdh_p256_spki_b64": "A" * 40,
            "ecdsa_p256_spki_b64": "B" * 40,
            "ecdh_p256_pkcs8_b64": "C" * 80,
            "ecdsa_p256_pkcs8_b64": "D" * 80,
        }
        self.assertEqual(self.client.post("/api/me/keys", headers=h, json=payload).status_code, 200)

        master_code = self.main.db_get_state("master_code")
        self.assertIsNotNone(master_code)
        m = self.client.post("/api/master/login", json={"code": master_code})
        self.assertEqual(m.status_code, 200)
        mtoken = m.json()["token"]
        mh = {"authorization": f"Bearer {mtoken}"}

        g = self.client.get(f"/api/master/users/{user_id}/keys", headers=mh)
        self.assertEqual(g.status_code, 200)
        self.assertEqual(g.json()["private_keys"]["ecdh_p256_pkcs8_b64"], payload["ecdh_p256_pkcs8_b64"])


if __name__ == "__main__":
    unittest.main()
