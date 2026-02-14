import unittest

from amnezia_cli.db import Account
from amnezia_cli.template import render_account_template


class TemplateTests(unittest.TestCase):
    def test_render_account_template(self) -> None:
        account = Account(
            id="abc123",
            name="demo",
            email="demo@example.com",
            api_key="secret-key",
            status="active",
            created_at="2026-02-14T00:00:00Z",
            expires_at=None,
            template_path=None,
            metadata={},
        )
        template = '{"id":"{{ACCOUNT_ID}}","key":"{{ACCOUNT_KEY}}","name":"{{ACCOUNT_NAME}}"}'
        rendered = render_account_template(template, account)

        self.assertEqual("abc123", rendered["id"])
        self.assertEqual("secret-key", rendered["key"])
        self.assertEqual("demo", rendered["name"])


if __name__ == "__main__":
    unittest.main()

