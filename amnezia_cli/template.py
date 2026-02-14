from __future__ import annotations

import json
from typing import Any

from amnezia_cli.db import Account


def build_template_context(account: Account) -> dict[str, str]:
    return {
        "ACCOUNT_ID": account.id,
        "ACCOUNT_NAME": account.name,
        "ACCOUNT_EMAIL": account.email or "",
        "ACCOUNT_KEY": account.api_key,
        "ACCOUNT_CREATED_AT": account.created_at,
        "ACCOUNT_EXPIRES_AT": account.expires_at or "",
        "ACCOUNT_STATUS": account.status,
    }


def render_account_template(template_text: str, account: Account) -> dict[str, Any]:
    rendered = template_text
    for key, value in build_template_context(account).items():
        rendered = rendered.replace(f"{{{{{key}}}}}", value)
    data = json.loads(rendered)
    if not isinstance(data, dict):
        raise ValueError("Config template must produce a JSON object")
    return data

