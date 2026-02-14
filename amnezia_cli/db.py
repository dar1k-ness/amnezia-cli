from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_urlsafe
from typing import Any, Optional


DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "amnezia-cli" / "accounts.db"


@dataclass(frozen=True)
class Account:
    id: str
    name: str
    email: Optional[str]
    api_key: str
    status: str
    created_at: str
    expires_at: Optional[str]
    template_path: Optional[str]
    metadata: dict[str, Any]


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _row_to_account(row: sqlite3.Row) -> Account:
    metadata = row["metadata_json"] or "{}"
    return Account(
        id=row["id"],
        name=row["name"],
        email=row["email"],
        api_key=row["api_key"],
        status=row["status"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        template_path=row["template_path"],
        metadata=json.loads(metadata),
    )


def open_db(path: Optional[Path] = None) -> sqlite3.Connection:
    db_path = path or DEFAULT_DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    ensure_schema(conn)
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT,
            api_key TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            expires_at TEXT,
            template_path TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
        """
    )
    conn.commit()


def create_account(
    conn: sqlite3.Connection,
    name: str,
    *,
    email: Optional[str] = None,
    expires_at: Optional[str] = None,
    template_path: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> Account:
    account_id = uuid.uuid4().hex[:12]
    api_key = token_urlsafe(24)
    created_at = _utc_now()
    metadata_json = json.dumps(metadata or {}, ensure_ascii=True, separators=(",", ":"))

    conn.execute(
        """
        INSERT INTO accounts (id, name, email, api_key, status, created_at, expires_at, template_path, metadata_json)
        VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)
        """,
        (account_id, name, email, api_key, created_at, expires_at, template_path, metadata_json),
    )
    conn.commit()
    return get_account(conn, account_id)


def get_account(conn: sqlite3.Connection, account_id: str) -> Account:
    row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    if row is None:
        raise KeyError(f"Account '{account_id}' not found")
    return _row_to_account(row)


def list_accounts(
    conn: sqlite3.Connection,
    *,
    include_revoked: bool = False,
    limit: int = 100,
) -> list[Account]:
    if include_revoked:
        rows = conn.execute(
            "SELECT * FROM accounts ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM accounts WHERE status = 'active' ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_row_to_account(row) for row in rows]


def revoke_account(conn: sqlite3.Connection, account_id: str) -> Account:
    result = conn.execute("UPDATE accounts SET status = 'revoked' WHERE id = ?", (account_id,))
    if result.rowcount == 0:
        raise KeyError(f"Account '{account_id}' not found")
    conn.commit()
    return get_account(conn, account_id)
