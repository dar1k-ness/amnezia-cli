import tempfile
import unittest
from pathlib import Path

from amnezia_cli.db import create_account, list_accounts, open_db, revoke_account


class DbAccountTests(unittest.TestCase):
    def test_create_list_revoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "accounts.db"
            with open_db(db_path) as conn:
                account = create_account(conn, "alice", email="alice@example.com")
                self.assertEqual("alice", account.name)
                self.assertEqual("active", account.status)

                active = list_accounts(conn)
                self.assertEqual(1, len(active))
                self.assertEqual(account.id, active[0].id)

                revoked = revoke_account(conn, account.id)
                self.assertEqual("revoked", revoked.status)

                active_after = list_accounts(conn)
                self.assertEqual(0, len(active_after))

                all_rows = list_accounts(conn, include_revoked=True)
                self.assertEqual(1, len(all_rows))
                self.assertEqual("revoked", all_rows[0].status)


if __name__ == "__main__":
    unittest.main()
