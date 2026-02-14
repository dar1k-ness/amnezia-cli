from __future__ import annotations

import argparse
import json
import os
import sys
from contextlib import closing
from pathlib import Path
from typing import Any, Optional

from amnezia_cli.db import (
    DEFAULT_DB_PATH,
    Account,
    create_account,
    get_account,
    list_accounts,
    open_db,
    revoke_account,
)
from amnezia_cli.selfhosted_awg import (
    CommandError,
    delete_awg_accounts,
    issue_awg_account,
    list_awg_accounts,
)
from amnezia_cli.template import render_account_template
from amnezia_cli.token_codec import decode_token, encode_token


def _resolve_db_path(path_arg: Optional[str]) -> Path:
    if path_arg:
        return Path(path_arg).expanduser()
    env_path = os.getenv("AMNEZIA_CLI_DB")
    if env_path:
        return Path(env_path).expanduser()
    return DEFAULT_DB_PATH


def _account_to_dict(account: Account, *, include_secret: bool = False) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": account.id,
        "name": account.name,
        "email": account.email,
        "status": account.status,
        "created_at": account.created_at,
        "expires_at": account.expires_at,
        "template_path": account.template_path,
        "metadata": account.metadata,
    }
    if include_secret:
        data["api_key"] = account.api_key
    return data


def _print_account_line(account: Account) -> None:
    email = account.email or "-"
    print(
        f"{account.id:12}  {account.status:7}  {account.name:20}  {email:25}  {account.created_at}"
    )


def _prefer_local_docker(args: argparse.Namespace) -> None:
    if args.vps_container:
        return
    if not args.direct:
        args.direct = True


def cmd_user_add(args: argparse.Namespace) -> int:
    _prefer_local_docker(args)
    return cmd_selfhosted_awg_add(args)


def cmd_user_list(args: argparse.Namespace) -> int:
    _prefer_local_docker(args)
    return cmd_selfhosted_awg_list(args)


def cmd_user_show(args: argparse.Namespace) -> int:
    _prefer_local_docker(args)
    return cmd_selfhosted_awg_show(args)


def cmd_user_del(args: argparse.Namespace) -> int:
    _prefer_local_docker(args)
    return cmd_selfhosted_awg_del(args)


def cmd_account_create(args: argparse.Namespace) -> int:
    metadata = {}
    if args.meta:
        metadata = json.loads(args.meta)
        if not isinstance(metadata, dict):
            raise ValueError("--meta must be a JSON object")

    db_path = _resolve_db_path(args.db)
    with closing(open_db(db_path)) as conn:
        account = create_account(
            conn,
            args.name,
            email=args.email,
            expires_at=args.expires_at,
            template_path=args.template,
            metadata=metadata,
        )

    if args.json:
        print(json.dumps(_account_to_dict(account, include_secret=True), indent=2, ensure_ascii=False))
    else:
        print(f"account_id={account.id}")
        print(f"api_key={account.api_key}")
    return 0


def cmd_account_list(args: argparse.Namespace) -> int:
    db_path = _resolve_db_path(args.db)
    with closing(open_db(db_path)) as conn:
        accounts = list_accounts(conn, include_revoked=args.all, limit=args.limit)

    if args.json:
        print(json.dumps([_account_to_dict(item) for item in accounts], indent=2, ensure_ascii=False))
        return 0

    print("id            status   name                  email                      created_at")
    print("-" * 88)
    for account in accounts:
        _print_account_line(account)
    return 0


def cmd_account_show(args: argparse.Namespace) -> int:
    db_path = _resolve_db_path(args.db)
    with closing(open_db(db_path)) as conn:
        account = get_account(conn, args.account_id)

    payload = _account_to_dict(account, include_secret=args.with_secret)
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        for key, value in payload.items():
            print(f"{key}={value}")
    return 0


def cmd_account_revoke(args: argparse.Namespace) -> int:
    db_path = _resolve_db_path(args.db)
    with closing(open_db(db_path)) as conn:
        account = revoke_account(conn, args.account_id)

    if args.json:
        print(json.dumps(_account_to_dict(account), indent=2, ensure_ascii=False))
    else:
        print(f"revoked_account_id={account.id}")
    return 0


def cmd_token_issue(args: argparse.Namespace) -> int:
    db_path = _resolve_db_path(args.db)
    with closing(open_db(db_path)) as conn:
        account = get_account(conn, args.account_id)
    if account.status != "active":
        raise ValueError(f"Account '{account.id}' is not active")

    template_path = args.config or account.template_path
    if not template_path:
        raise ValueError("Config template is not provided. Use --config or set --template when creating the account.")

    template_text = Path(template_path).read_text(encoding="utf-8")
    rendered_config = render_account_template(template_text, account)
    payload = json.dumps(rendered_config, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    token = encode_token(payload, with_signature=args.signature)

    if args.out:
        Path(args.out).write_text(token + "\n", encoding="utf-8")

    if args.json:
        print(
            json.dumps(
                {
                    "account_id": account.id,
                    "signature_mode": args.signature,
                    "payload_bytes": len(payload),
                    "token": token,
                    "written_to": args.out,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(token)
    return 0


def cmd_token_decode(args: argparse.Namespace) -> int:
    token_value = args.token
    if args.token_file:
        token_value = Path(args.token_file).read_text(encoding="utf-8").strip()
    if not token_value:
        raise ValueError("Token is empty")

    decoded = decode_token(token_value)
    payload_text = decoded.payload.decode("utf-8")

    if args.json:
        maybe_json: Any
        try:
            maybe_json = json.loads(payload_text)
        except json.JSONDecodeError:
            maybe_json = payload_text
        print(
            json.dumps(
                {
                    "signature_mode": decoded.used_signature,
                    "payload": maybe_json,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(payload_text)
    return 0


def cmd_selfhosted_awg_add(args: argparse.Namespace) -> int:
    username = args.username.strip()
    if not username:
        raise ValueError("username must not be empty")

    _prefer_local_docker(args)

    default_wg_config_path = "/opt/amnezia/awg/wg0.conf"
    default_psk_path = "/opt/amnezia/awg/wireguard_psk.key"
    result = issue_awg_account(
        awg_container=args.awg_container or "amnezia-awg",
        vps_container=args.vps_container,
        wg_config_path=args.wg_config_path or default_wg_config_path,
        psk_path=args.psk_path or default_psk_path,
        endpoint_host=args.endpoint_host,
        endpoint_port=args.endpoint_port,
        dns=args.dns,
        allowed_ips=args.allowed_ips,
        keepalive=args.keepalive,
        peer_name=username,
        direct=args.direct,
    )

    if args.out_token:
        Path(args.out_token).write_text(result.token + "\n", encoding="utf-8")
    if args.out_config:
        Path(args.out_config).write_text(result.config_text, encoding="utf-8")

    if args.json:
        print(
            json.dumps(
                {
                    "token": result.token,
                    "client_ip": result.client_ip,
                    "client_public_key": result.client_public_key,
                    "endpoint_host": result.endpoint_host,
                    "endpoint_port": result.endpoint_port,
                    "username": username,
                    "awg_container": result.awg_container,
                    "vps_container": result.vps_container,
                    "interface_name": result.interface_name,
                    "written_token": args.out_token,
                    "written_config": args.out_config,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(result.token)
    return 0


def cmd_selfhosted_awg_list(args: argparse.Namespace) -> int:
    _prefer_local_docker(args)

    default_wg_config_path = "/opt/amnezia/awg/wg0.conf"
    result = list_awg_accounts(
        awg_container=args.awg_container or "amnezia-awg",
        vps_container=args.vps_container,
        wg_config_path=args.wg_config_path or default_wg_config_path,
        direct=args.direct,
    )

    if args.json:
        print(
            json.dumps(
                {
                    "awg_container": result.awg_container,
                    "vps_container": result.vps_container,
                    "interface_name": result.interface_name,
                    "count": len(result.peers),
                    "users": [
                        {
                            "username": item.username,
                            "client_ip": item.client_ip,
                            "public_key": item.public_key,
                            "allowed_ips": item.allowed_ips,
                            "endpoint": item.endpoint,
                            "last_handshake": item.last_handshake,
                            "transfer_rx": item.transfer_rx,
                            "transfer_tx": item.transfer_tx,
                        }
                        for item in result.peers
                    ],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    print(
        f"awg_container={result.awg_container} interface={result.interface_name} source={result.vps_container or 'local-docker'}"
    )
    print("username           client_ip         public_key                                   rx/tx")
    print("-" * 96)
    for item in result.peers:
        username = item.username or "-"
        client_ip = item.client_ip or "-"
        public_key = item.public_key[:42]
        rx = item.transfer_rx if item.transfer_rx is not None else 0
        tx = item.transfer_tx if item.transfer_tx is not None else 0
        print(f"{username:18} {client_ip:16} {public_key:42} {rx}/{tx}")
    return 0


def cmd_selfhosted_awg_show(args: argparse.Namespace) -> int:
    username = args.username.strip()
    if not username:
        raise ValueError("username must not be empty")

    _prefer_local_docker(args)

    default_wg_config_path = "/opt/amnezia/awg/wg0.conf"
    result = list_awg_accounts(
        awg_container=args.awg_container or "amnezia-awg",
        vps_container=args.vps_container,
        wg_config_path=args.wg_config_path or default_wg_config_path,
        direct=args.direct,
    )

    filtered = [item for item in result.peers if item.username == username]
    if not filtered:
        raise ValueError(f"No peers found for username '{username}'")

    if args.json:
        print(
            json.dumps(
                {
                    "awg_container": result.awg_container,
                    "vps_container": result.vps_container,
                    "interface_name": result.interface_name,
                    "username": username,
                    "count": len(filtered),
                    "users": [
                        {
                            "username": item.username,
                            "client_ip": item.client_ip,
                            "public_key": item.public_key,
                            "allowed_ips": item.allowed_ips,
                            "endpoint": item.endpoint,
                            "last_handshake": item.last_handshake,
                            "transfer_rx": item.transfer_rx,
                            "transfer_tx": item.transfer_tx,
                        }
                        for item in filtered
                    ],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    print(
        f"awg_container={result.awg_container} interface={result.interface_name} source={result.vps_container or 'local-docker'}"
    )
    print("username           client_ip         public_key                                   rx/tx")
    print("-" * 96)
    for item in filtered:
        client_ip = item.client_ip or "-"
        public_key = item.public_key[:42]
        rx = item.transfer_rx if item.transfer_rx is not None else 0
        tx = item.transfer_tx if item.transfer_tx is not None else 0
        print(f"{username:18} {client_ip:16} {public_key:42} {rx}/{tx}")
    return 0


def cmd_selfhosted_awg_del(args: argparse.Namespace) -> int:
    username = args.username.strip()
    if not username:
        raise ValueError("username must not be empty")

    _prefer_local_docker(args)

    default_wg_config_path = "/opt/amnezia/awg/wg0.conf"
    result = delete_awg_accounts(
        awg_container=args.awg_container or "amnezia-awg",
        vps_container=args.vps_container,
        wg_config_path=args.wg_config_path or default_wg_config_path,
        username=username,
        public_key=args.public_key,
        dry_run=args.dry_run,
        direct=args.direct,
    )

    if args.json:
        print(
            json.dumps(
                {
                    "action": "dry-run" if result.dry_run else "deleted",
                    "username": result.username,
                    "removed_count": len(result.removed),
                    "awg_container": result.awg_container,
                    "vps_container": result.vps_container,
                    "interface_name": result.interface_name,
                    "removed": [
                        {
                            "username": item.username,
                            "client_ip": item.client_ip,
                            "public_key": item.public_key,
                            "allowed_ips": item.allowed_ips,
                            "endpoint": item.endpoint,
                            "last_handshake": item.last_handshake,
                            "transfer_rx": item.transfer_rx,
                            "transfer_tx": item.transfer_tx,
                        }
                        for item in result.removed
                    ],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    action = "would_remove" if result.dry_run else "removed"
    print(
        f"{action}={len(result.removed)} username={result.username} "
        f"awg_container={result.awg_container} interface={result.interface_name} "
        f"source={result.vps_container or 'local-docker'}"
    )
    if result.removed:
        print("username           client_ip         public_key")
        print("-" * 80)
        for item in result.removed:
            peer_user = item.username or "-"
            peer_ip = item.client_ip or "-"
            peer_key = item.public_key[:42]
            print(f"{peer_user:18} {peer_ip:16} {peer_key}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="amz", description="Manage AmneziaVPN accounts and vpn:// tokens")
    parser.add_argument("--db", help="Path to SQLite DB (or use AMNEZIA_CLI_DB)")

    subparsers = parser.add_subparsers(dest="entity", required=True)

    account_parser = subparsers.add_parser("account", help="Account management commands")
    account_sub = account_parser.add_subparsers(dest="account_command", required=True)

    account_create = account_sub.add_parser("create", help="Create an account")
    account_create.add_argument("--name", required=True, help="Human-readable account name")
    account_create.add_argument("--email", help="Optional account email")
    account_create.add_argument("--expires-at", help="Optional ISO-8601 expiry date")
    account_create.add_argument("--template", help="Default JSON template path for this account")
    account_create.add_argument("--meta", help="Optional metadata JSON object")
    account_create.add_argument("--json", action="store_true", help="Print result as JSON")
    account_create.set_defaults(func=cmd_account_create)

    account_list = account_sub.add_parser("list", help="List accounts")
    account_list.add_argument("--all", action="store_true", help="Include revoked accounts")
    account_list.add_argument("--limit", type=int, default=100, help="Max rows")
    account_list.add_argument("--json", action="store_true", help="Print result as JSON")
    account_list.set_defaults(func=cmd_account_list)

    account_show = account_sub.add_parser("show", help="Show account details")
    account_show.add_argument("account_id", help="Account ID")
    account_show.add_argument("--with-secret", action="store_true", help="Include API key in output")
    account_show.add_argument("--json", action="store_true", help="Print result as JSON")
    account_show.set_defaults(func=cmd_account_show)

    account_revoke = account_sub.add_parser("revoke", help="Revoke account")
    account_revoke.add_argument("account_id", help="Account ID")
    account_revoke.add_argument("--json", action="store_true", help="Print result as JSON")
    account_revoke.set_defaults(func=cmd_account_revoke)

    token_parser = subparsers.add_parser("token", help="Token management commands")
    token_sub = token_parser.add_subparsers(dest="token_command", required=True)

    token_issue = token_sub.add_parser("issue", help="Generate vpn:// token from account + JSON template")
    token_issue.add_argument("--account-id", required=True, help="Account ID")
    token_issue.add_argument("--config", help="Path to JSON template file (optional if account has template)")
    token_issue.add_argument("--signature", action="store_true", help="Use subscription signature mode (000000ff)")
    token_issue.add_argument("--out", help="Write token to file")
    token_issue.add_argument("--json", action="store_true", help="Print result as JSON")
    token_issue.set_defaults(func=cmd_token_issue)

    token_decode = token_sub.add_parser("decode", help="Decode vpn:// token")
    token_source = token_decode.add_mutually_exclusive_group(required=True)
    token_source.add_argument("--token", help="Token value")
    token_source.add_argument("--token-file", help="Read token from file")
    token_decode.add_argument("--json", action="store_true", help="Print result as JSON")
    token_decode.set_defaults(func=cmd_token_decode)

    user_parser = subparsers.add_parser("user", help="Manage AWG users on local server")
    user_sub = user_parser.add_subparsers(dest="user_command", required=True)

    user_add = user_sub.add_parser("add", help="Create user key and return vpn:// token")
    user_add.add_argument("username", help="Username label for the new key")
    user_add.add_argument("--endpoint-host", help="Override endpoint host/IP (auto-detected by default)")
    user_add.add_argument("--endpoint-port", type=int, help="Public endpoint port (default: detect from server)")
    user_add.add_argument("--dns", default="1.1.1.1", help="DNS for client config")
    user_add.add_argument("--allowed-ips", default="0.0.0.0/0, ::/0", help="AllowedIPs in client config")
    user_add.add_argument("--keepalive", type=int, default=25, help="PersistentKeepalive value")
    user_add.add_argument("--vps-container", help="Override outer VPS container name for nested docker mode")
    user_add.add_argument("--direct", action="store_true", help="Force direct host docker mode")
    user_add.add_argument("--awg-container", help="Override AWG container name")
    user_add.add_argument("--wg-config-path", help="Override path to wg config in AWG container")
    user_add.add_argument("--psk-path", help="Override path to PSK file in AWG container")
    user_add.add_argument("--out-token", help="Write vpn:// token to file")
    user_add.add_argument("--out-config", help="Write generated client config to file")
    user_add.add_argument("--json", action="store_true", help="Print result as JSON")
    user_add.set_defaults(func=cmd_user_add)

    user_list = user_sub.add_parser("list", help="List users/peers")
    user_list.add_argument("--vps-container", help="Override outer VPS container name for nested docker mode")
    user_list.add_argument("--direct", action="store_true", help="Force direct host docker mode")
    user_list.add_argument("--awg-container", help="Override AWG container name")
    user_list.add_argument("--wg-config-path", help="Override path to wg config in AWG container")
    user_list.add_argument("--json", action="store_true", help="Print result as JSON")
    user_list.set_defaults(func=cmd_user_list)

    user_show = user_sub.add_parser("show", help="Show one user")
    user_show.add_argument("username", help="Username label")
    user_show.add_argument("--vps-container", help="Override outer VPS container name for nested docker mode")
    user_show.add_argument("--direct", action="store_true", help="Force direct host docker mode")
    user_show.add_argument("--awg-container", help="Override AWG container name")
    user_show.add_argument("--wg-config-path", help="Override path to wg config in AWG container")
    user_show.add_argument("--json", action="store_true", help="Print result as JSON")
    user_show.set_defaults(func=cmd_user_show)

    user_del = user_sub.add_parser("del", aliases=["rm", "remove"], help="Delete user keys")
    user_del.add_argument("username", help="Username label to delete")
    user_del.add_argument("--public-key", help="Delete only peer with this public key")
    user_del.add_argument("--dry-run", action="store_true", help="Only show what would be removed")
    user_del.add_argument("--vps-container", help="Override outer VPS container name for nested docker mode")
    user_del.add_argument("--direct", action="store_true", help="Force direct host docker mode")
    user_del.add_argument("--awg-container", help="Override AWG container name")
    user_del.add_argument("--wg-config-path", help="Override path to wg config in AWG container")
    user_del.add_argument("--json", action="store_true", help="Print result as JSON")
    user_del.set_defaults(func=cmd_user_del)

    selfhosted_parser = subparsers.add_parser("selfhosted", help="Local AWG management")
    selfhosted_sub = selfhosted_parser.add_subparsers(dest="selfhosted_command", required=True)

    selfhosted_awg_add = selfhosted_sub.add_parser("awg-add", help="Create AWG peer and return vpn:// token")
    selfhosted_awg_add.add_argument("username", help="Username label for the new key")
    selfhosted_awg_add.add_argument("--endpoint-host", help="Override endpoint host/IP (auto-detected by default)")
    selfhosted_awg_add.add_argument("--endpoint-port", type=int, help="Public endpoint port (default: detect from server)")
    selfhosted_awg_add.add_argument("--dns", default="1.1.1.1", help="DNS for client config")
    selfhosted_awg_add.add_argument("--allowed-ips", default="0.0.0.0/0, ::/0", help="AllowedIPs in client config")
    selfhosted_awg_add.add_argument("--keepalive", type=int, default=25, help="PersistentKeepalive value")

    selfhosted_awg_add.add_argument("--vps-container", help="Override outer VPS container name for nested docker mode")
    selfhosted_awg_add.add_argument("--direct", action="store_true", help="Force direct host docker mode")
    selfhosted_awg_add.add_argument("--awg-container", help="Override AWG container name")
    selfhosted_awg_add.add_argument("--wg-config-path", help="Override path to wg config in AWG container")
    selfhosted_awg_add.add_argument("--psk-path", help="Override path to PSK file in AWG container")
    selfhosted_awg_add.add_argument("--out-token", help="Write vpn:// token to file")
    selfhosted_awg_add.add_argument("--out-config", help="Write generated client config to file")
    selfhosted_awg_add.add_argument("--json", action="store_true", help="Print result as JSON")
    selfhosted_awg_add.set_defaults(func=cmd_selfhosted_awg_add)

    selfhosted_awg_list = selfhosted_sub.add_parser("awg-list", help="List AWG users/peers")
    selfhosted_awg_list.add_argument("--vps-container", help="Override outer VPS container name for nested docker mode")
    selfhosted_awg_list.add_argument("--direct", action="store_true", help="Force direct host docker mode")
    selfhosted_awg_list.add_argument("--awg-container", help="Override AWG container name")
    selfhosted_awg_list.add_argument("--wg-config-path", help="Override path to wg config in AWG container")
    selfhosted_awg_list.add_argument("--json", action="store_true", help="Print result as JSON")
    selfhosted_awg_list.set_defaults(func=cmd_selfhosted_awg_list)

    selfhosted_awg_show = selfhosted_sub.add_parser("awg-show", help="Show AWG peers for one username")
    selfhosted_awg_show.add_argument("username", help="Username label")
    selfhosted_awg_show.add_argument("--vps-container", help="Override outer VPS container name for nested docker mode")
    selfhosted_awg_show.add_argument("--direct", action="store_true", help="Force direct host docker mode")
    selfhosted_awg_show.add_argument("--awg-container", help="Override AWG container name")
    selfhosted_awg_show.add_argument("--wg-config-path", help="Override path to wg config in AWG container")
    selfhosted_awg_show.add_argument("--json", action="store_true", help="Print result as JSON")
    selfhosted_awg_show.set_defaults(func=cmd_selfhosted_awg_show)

    selfhosted_awg_del = selfhosted_sub.add_parser(
        "awg-del",
        aliases=["awg-rm", "awg-remove"],
        help="Delete AWG peers by username label",
    )
    selfhosted_awg_del.add_argument("username", help="Username label to delete")
    selfhosted_awg_del.add_argument("--public-key", help="Delete only peer with this public key")
    selfhosted_awg_del.add_argument("--dry-run", action="store_true", help="Only show what would be removed")
    selfhosted_awg_del.add_argument("--vps-container", help="Override outer VPS container name for nested docker mode")
    selfhosted_awg_del.add_argument("--direct", action="store_true", help="Force direct host docker mode")
    selfhosted_awg_del.add_argument("--awg-container", help="Override AWG container name")
    selfhosted_awg_del.add_argument("--wg-config-path", help="Override path to wg config in AWG container")
    selfhosted_awg_del.add_argument("--json", action="store_true", help="Print result as JSON")
    selfhosted_awg_del.set_defaults(func=cmd_selfhosted_awg_del)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (ValueError, json.JSONDecodeError, CommandError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
