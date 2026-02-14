from __future__ import annotations

import base64
import ipaddress
import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from amnezia_cli.token_codec import encode_token


AWG_PARAM_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")
COMMON_WG_CONFIG_PATHS = (
    "/opt/amnezia/awg/wg0.conf",
    "/opt/amnezia/awg/awg0.conf",
    "/opt/amnezia/wireguard/wg0.conf",
    "/opt/amnezia/wireguard/awg0.conf",
    "/opt/amnezia/amnezia-wg/wg0.conf",
    "/opt/amnezia/amnezia-wg/awg0.conf",
    "/etc/wireguard/wg0.conf",
    "/etc/wireguard/awg0.conf",
)
COMMON_PSK_PATHS = (
    "/opt/amnezia/awg/wireguard_psk.key",
    "/opt/amnezia/wireguard/wireguard_psk.key",
    "/opt/amnezia/amnezia-wg/wireguard_psk.key",
    "/etc/wireguard/wireguard_psk.key",
)


@dataclass(frozen=True)
class ParsedAwgConfig:
    interface: dict[str, str]
    peers: list[dict[str, str]]


@dataclass(frozen=True)
class IssuedAwgAccount:
    token: str
    config_text: str
    client_private_key: str
    client_public_key: str
    client_ip: str
    endpoint_host: str
    endpoint_port: int
    awg_container: str
    vps_container: Optional[str]
    interface_name: str


@dataclass(frozen=True)
class AwgPeer:
    username: Optional[str]
    public_key: str
    allowed_ips: str
    client_ip: Optional[str]
    endpoint: Optional[str]
    last_handshake: Optional[int]
    transfer_rx: Optional[int]
    transfer_tx: Optional[int]
    persistent_keepalive: Optional[int]


@dataclass(frozen=True)
class AwgPeerList:
    peers: list[AwgPeer]
    awg_container: str
    vps_container: Optional[str]
    interface_name: str


@dataclass(frozen=True)
class DeletedAwgPeers:
    removed: list[AwgPeer]
    awg_container: str
    vps_container: Optional[str]
    interface_name: str
    username: str
    dry_run: bool


@dataclass(frozen=True)
class _PeerBlock:
    remove_start: int
    remove_end: int
    label: Optional[str]
    public_key: Optional[str]
    allowed_ips: str


class CommandError(RuntimeError):
    pass


@dataclass(frozen=True)
class AwgContext:
    awg_container: str
    vps_container: Optional[str]
    wg_config_path: str


def _run_capture(cmd: list[str], env: Optional[dict[str, str]] = None) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        stdout = proc.stdout.strip()
        detail = stderr or stdout or "unknown error"
        if "docker.sock" in detail and "permission denied" in detail.lower():
            detail = (
                detail
                + "\nHint: add your user to docker group, then relogin or run `newgrp docker`."
            )
        raise CommandError(f"Command failed: {' '.join(cmd)}\n{detail}")
    return proc.stdout


def _docker_ps_names(prefix: list[str]) -> list[str]:
    out = _run_capture(prefix + ["ps", "--format", "{{.Names}}"])
    return [line.strip() for line in out.splitlines() if line.strip()]


def _container_has_file(prefix: list[str], container: str, file_path: str) -> bool:
    proc = subprocess.run(prefix + ["exec", container, "test", "-f", file_path], capture_output=True, text=True)
    return proc.returncode == 0


def _build_path_candidates(primary: Optional[str], common: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for path in [primary, *common]:
        if path and path not in out:
            out.append(path)
    return out


def _find_awg_in_scope(prefix: list[str], preferred_awg: Optional[str], wg_config_path: str) -> Optional[tuple[str, str]]:
    try:
        names = _docker_ps_names(prefix)
    except CommandError:
        return None

    candidates: list[str] = []
    if preferred_awg:
        candidates.append(preferred_awg)
    candidates.extend([name for name in names if name not in candidates and "amnezia-awg" in name])
    candidates.extend([name for name in names if name not in candidates])

    wg_paths = _build_path_candidates(wg_config_path, COMMON_WG_CONFIG_PATHS)
    for name in candidates:
        for path in wg_paths:
            if _container_has_file(prefix, name, path):
                return name, path
    return None


def detect_awg_context(
    *,
    wg_config_path: str,
    preferred_awg: Optional[str],
    preferred_vps: Optional[str],
    direct: bool,
) -> AwgContext:
    direct_prefix = ["docker"]

    if direct:
        found = _find_awg_in_scope(direct_prefix, preferred_awg, wg_config_path)
        if found:
            awg_name, resolved_path = found
            return AwgContext(awg_container=awg_name, vps_container=None, wg_config_path=resolved_path)
        raise CommandError("AWG container not found on host docker daemon")

    tried_vps: list[str] = []
    for vps_name in [preferred_vps]:
        if not vps_name or vps_name in tried_vps:
            continue
        tried_vps.append(vps_name)
        nested_prefix = ["docker", "exec", vps_name, "docker"]
        found = _find_awg_in_scope(nested_prefix, preferred_awg, wg_config_path)
        if found:
            awg_name, resolved_path = found
            return AwgContext(awg_container=awg_name, vps_container=vps_name, wg_config_path=resolved_path)

    # fallback: look for any container that exposes nested docker
    host_names = _docker_ps_names(direct_prefix)
    for vps_name in host_names:
        if vps_name in tried_vps:
            continue
        nested_prefix = ["docker", "exec", vps_name, "docker"]
        found = _find_awg_in_scope(nested_prefix, preferred_awg, wg_config_path)
        if found:
            awg_name, resolved_path = found
            return AwgContext(awg_container=awg_name, vps_container=vps_name, wg_config_path=resolved_path)

    # final fallback: AWG might be directly on host
    found = _find_awg_in_scope(direct_prefix, preferred_awg, wg_config_path)
    if found:
        awg_name, resolved_path = found
        return AwgContext(awg_container=awg_name, vps_container=None, wg_config_path=resolved_path)

    raise CommandError("Could not auto-detect AWG container")


def parse_wg_config(config_text: str) -> ParsedAwgConfig:
    section = ""
    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    current_peer: dict[str, str] = {}

    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            if section == "Peer" and current_peer:
                peers.append(current_peer)
                current_peer = {}
            section = line[1:-1].strip()
            continue
        if "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if section == "Interface":
            interface[key] = value
        elif section == "Peer":
            current_peer[key] = value

    if section == "Peer" and current_peer:
        peers.append(current_peer)

    return ParsedAwgConfig(interface=interface, peers=peers)


def parse_wg_peer_blocks(config_text: str) -> list[dict[str, str]]:
    section = ""
    pending_label: Optional[str] = None
    current_label: Optional[str] = None
    current_peer: dict[str, str] = {}
    peers: list[dict[str, str]] = []

    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            label_prefix = "# amnezia-cli:"
            lower_line = line.lower()
            if lower_line.startswith(label_prefix):
                pending_label = line[len(label_prefix) :].strip()
            continue
        if line.startswith("[") and line.endswith("]"):
            if section == "Peer" and current_peer:
                if current_label:
                    current_peer["_label"] = current_label
                peers.append(current_peer)
                current_peer = {}
                current_label = None
            section = line[1:-1].strip()
            if section == "Peer":
                current_label = pending_label
                pending_label = None
            continue
        if section != "Peer":
            continue
        if "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        current_peer[key] = value

    if section == "Peer" and current_peer:
        if current_label:
            current_peer["_label"] = current_label
        peers.append(current_peer)

    return peers


def _collect_peer_blocks(config_text: str) -> list[_PeerBlock]:
    lines = config_text.splitlines(keepends=True)
    blocks: list[_PeerBlock] = []
    pending_label: Optional[str] = None
    pending_label_line: Optional[int] = None
    idx = 0

    while idx < len(lines):
        stripped = lines[idx].strip()
        if not stripped:
            idx += 1
            continue
        if stripped.startswith("#"):
            label_prefix = "# amnezia-cli:"
            lower_line = stripped.lower()
            if lower_line.startswith(label_prefix):
                pending_label = stripped[len(label_prefix) :].strip()
                pending_label_line = idx
            idx += 1
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            if section != "Peer":
                idx += 1
                continue

            remove_start = idx
            current_label: Optional[str] = None
            if pending_label is not None and pending_label_line is not None:
                if all(not lines[pos].strip() for pos in range(pending_label_line + 1, idx)):
                    remove_start = pending_label_line
                    current_label = pending_label

            values: dict[str, str] = {}
            end = idx + 1
            while end < len(lines):
                candidate = lines[end].strip()
                if candidate.startswith("[") and candidate.endswith("]"):
                    break
                if candidate.lower().startswith("# amnezia-cli:"):
                    break
                if candidate and not candidate.startswith("#") and "=" in candidate:
                    key, value = [part.strip() for part in candidate.split("=", 1)]
                    values[key] = value
                end += 1

            blocks.append(
                _PeerBlock(
                    remove_start=remove_start,
                    remove_end=end,
                    label=current_label,
                    public_key=values.get("PublicKey"),
                    allowed_ips=values.get("AllowedIPs", ""),
                )
            )
            pending_label = None
            pending_label_line = None
            idx = end
            continue
        idx += 1

    return blocks


def _parse_int_or_none(value: str) -> Optional[int]:
    stripped = value.strip()
    if not stripped or stripped in {"off", "(none)"}:
        return None
    if stripped.isdigit():
        return int(stripped)
    return None


def _looks_like_allowed_ips(value: str) -> bool:
    chunks = [item.strip() for item in value.split(",") if item.strip()]
    if not chunks:
        return False
    for item in chunks:
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            return False
    return True


def _parse_wg_dump(dump_text: str) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for raw_line in dump_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 8:
            parts = line.split()
        if len(parts) < 8:
            continue
        # Interface row has 4 columns in standard wg dump output.
        if len(parts) == 4:
            continue
        pubkey = parts[0].strip()
        if not pubkey or pubkey == "(none)":
            continue
        allowed_ips = parts[3].strip()
        if not _looks_like_allowed_ips(allowed_ips):
            continue
        result[pubkey] = {
            "endpoint": parts[2].strip(),
            "allowed_ips": allowed_ips,
            "last_handshake": parts[4].strip(),
            "transfer_rx": parts[5].strip(),
            "transfer_tx": parts[6].strip(),
            "persistent_keepalive": parts[7].strip(),
        }
    return result


def _extract_client_ip(allowed_ips: str) -> Optional[str]:
    for item in [chunk.strip() for chunk in allowed_ips.split(",") if chunk.strip()]:
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network) and net.prefixlen == 32:
            return str(net.network_address)
    return None


def _build_peer_from_block(block: _PeerBlock, runtime: dict[str, str]) -> AwgPeer:
    allowed_ips = runtime.get("allowed_ips") or block.allowed_ips
    endpoint = runtime.get("endpoint")
    if endpoint in {"", "(none)"}:
        endpoint = None
    return AwgPeer(
        username=block.label or None,
        public_key=block.public_key or "",
        allowed_ips=allowed_ips,
        client_ip=_extract_client_ip(allowed_ips),
        endpoint=endpoint,
        last_handshake=_parse_int_or_none(runtime.get("last_handshake", "")),
        transfer_rx=_parse_int_or_none(runtime.get("transfer_rx", "")),
        transfer_tx=_parse_int_or_none(runtime.get("transfer_tx", "")),
        persistent_keepalive=_parse_int_or_none(runtime.get("persistent_keepalive", "")),
    )


def _delete_peer_blocks_from_config(config_text: str, blocks_to_delete: list[_PeerBlock]) -> str:
    if not blocks_to_delete:
        return config_text
    lines = config_text.splitlines(keepends=True)
    to_remove: set[int] = set()
    for block in blocks_to_delete:
        to_remove.update(range(block.remove_start, block.remove_end))
    rendered = "".join(line for idx, line in enumerate(lines) if idx not in to_remove)
    if rendered and not rendered.endswith("\n"):
        rendered += "\n"
    return rendered


def _safe_wg_dump(executor: object, interface_name: str) -> str:
    run_shell = getattr(executor, "run_shell")
    if not callable(run_shell):
        return ""
    try:
        return run_shell(f"wg show {shlex.quote(interface_name)} dump")
    except CommandError:
        return ""


def _collect_peer_list(executor: object, *, awg_container: str, vps_container: Optional[str], wg_config_path: str) -> AwgPeerList:
    run = getattr(executor, "run")
    if not callable(run):
        raise CommandError("Executor does not support run")

    cfg_text = run(["cat", wg_config_path])
    peer_blocks = parse_wg_peer_blocks(cfg_text)
    interface_name = Path(wg_config_path).stem
    dump_map = _parse_wg_dump(_safe_wg_dump(executor, interface_name))

    peers: list[AwgPeer] = []
    seen: set[str] = set()
    for peer in peer_blocks:
        public_key = peer.get("PublicKey", "").strip()
        if not public_key:
            continue
        seen.add(public_key)
        runtime = dump_map.get(public_key, {})
        allowed_ips = runtime.get("allowed_ips") or peer.get("AllowedIPs", "")
        endpoint = runtime.get("endpoint")
        if endpoint in {"", "(none)"}:
            endpoint = None
        peers.append(
            AwgPeer(
                username=peer.get("_label") or None,
                public_key=public_key,
                allowed_ips=allowed_ips,
                client_ip=_extract_client_ip(allowed_ips),
                endpoint=endpoint,
                last_handshake=_parse_int_or_none(runtime.get("last_handshake", "")),
                transfer_rx=_parse_int_or_none(runtime.get("transfer_rx", "")),
                transfer_tx=_parse_int_or_none(runtime.get("transfer_tx", "")),
                persistent_keepalive=_parse_int_or_none(runtime.get("persistent_keepalive", "")),
            )
        )

    for public_key, runtime in dump_map.items():
        if public_key in seen:
            continue
        allowed_ips = runtime.get("allowed_ips", "")
        endpoint = runtime.get("endpoint")
        if endpoint in {"", "(none)"}:
            endpoint = None
        peers.append(
            AwgPeer(
                username=None,
                public_key=public_key,
                allowed_ips=allowed_ips,
                client_ip=_extract_client_ip(allowed_ips),
                endpoint=endpoint,
                last_handshake=_parse_int_or_none(runtime.get("last_handshake", "")),
                transfer_rx=_parse_int_or_none(runtime.get("transfer_rx", "")),
                transfer_tx=_parse_int_or_none(runtime.get("transfer_tx", "")),
                persistent_keepalive=_parse_int_or_none(runtime.get("persistent_keepalive", "")),
            )
        )

    peers.sort(key=lambda item: (item.client_ip is None, item.client_ip or "", item.public_key))
    return AwgPeerList(
        peers=peers,
        awg_container=awg_container,
        vps_container=vps_container,
        interface_name=interface_name,
    )


def _delete_awg_peers(
    executor: object,
    *,
    awg_container: str,
    vps_container: Optional[str],
    wg_config_path: str,
    username: str,
    public_key: Optional[str],
    dry_run: bool,
) -> DeletedAwgPeers:
    run = getattr(executor, "run")
    if not callable(run):
        raise CommandError("Executor does not support run")

    target_username = username.strip()
    if not target_username:
        raise CommandError("username must not be empty")

    cfg_text = run(["cat", wg_config_path])
    blocks = _collect_peer_blocks(cfg_text)
    matches = [block for block in blocks if block.label == target_username]
    if public_key:
        matches = [block for block in matches if block.public_key == public_key]

    if not matches:
        suffix = f" with public_key={public_key}" if public_key else ""
        raise CommandError(f"No peers found for username '{target_username}'{suffix}")

    interface_name = Path(wg_config_path).stem
    dump_map = _parse_wg_dump(_safe_wg_dump(executor, interface_name))

    removed: list[AwgPeer] = []
    for block in matches:
        if not block.public_key:
            continue
        removed.append(_build_peer_from_block(block, dump_map.get(block.public_key, {})))

    updated = _delete_peer_blocks_from_config(cfg_text, matches)
    if not dry_run:
        _replace_config_and_sync(
            executor,
            wg_config_path=wg_config_path,
            interface_name=interface_name,
            config_text=updated,
        )

    removed.sort(key=lambda item: (item.client_ip is None, item.client_ip or "", item.public_key))
    return DeletedAwgPeers(
        removed=removed,
        awg_container=awg_container,
        vps_container=vps_container,
        interface_name=interface_name,
        username=target_username,
        dry_run=dry_run,
    )


def extract_interface_network(config: ParsedAwgConfig) -> tuple[ipaddress.IPv4Interface, ipaddress.IPv4Network]:
    raw_address = config.interface.get("Address")
    if not raw_address:
        raise CommandError("WireGuard config does not contain Interface Address")

    for item in [part.strip() for part in raw_address.split(",")]:
        try:
            iface = ipaddress.ip_interface(item)
        except ValueError:
            continue
        if isinstance(iface, ipaddress.IPv4Interface):
            return iface, iface.network

    raise CommandError("WireGuard Interface Address does not contain an IPv4 CIDR")


def collect_used_client_ips(config: ParsedAwgConfig, server_iface: ipaddress.IPv4Interface) -> set[ipaddress.IPv4Address]:
    used: set[ipaddress.IPv4Address] = {server_iface.ip}
    for peer in config.peers:
        raw_allowed = peer.get("AllowedIPs", "")
        for item in [part.strip() for part in raw_allowed.split(",") if part.strip()]:
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError:
                continue
            if isinstance(net, ipaddress.IPv4Network) and net.prefixlen == 32:
                used.add(net.network_address)
    return used


def allocate_client_ip(network: ipaddress.IPv4Network, used: set[ipaddress.IPv4Address]) -> ipaddress.IPv4Address:
    for host in network.hosts():
        if host not in used:
            return host
    raise CommandError(f"No free client IPs left in network {network}")


class DockerAwgExecutor:
    def __init__(self, *, awg_container: str, vps_container: Optional[str] = None):
        self.awg_container = awg_container
        self.vps_container = vps_container

    def _prefix(self) -> list[str]:
        if self.vps_container:
            return ["docker", "exec", self.vps_container, "docker", "exec", self.awg_container]
        return ["docker", "exec", self.awg_container]

    def run(self, args: list[str]) -> str:
        return _run_capture(self._prefix() + args)

    def run_shell(self, script: str) -> str:
        return self.run(["bash", "-lc", script])


def _resolve_psk_path_local(
    *,
    prefix: list[str],
    container: str,
    preferred_psk_path: str,
    resolved_wg_config_path: str,
) -> str:
    candidates = _build_path_candidates(
        preferred_psk_path,
        (
            str(Path(resolved_wg_config_path).with_name("wireguard_psk.key")),
            *COMMON_PSK_PATHS,
        ),
    )
    for path in candidates:
        if _container_has_file(prefix, container, path):
            return path
    return preferred_psk_path


def _generate_client_keys(executor: object) -> tuple[str, str]:
    run_shell = getattr(executor, "run_shell")
    if not callable(run_shell):
        raise CommandError("Executor does not support run_shell")
    out = executor.run_shell(
        "set -euo pipefail; "
        "priv=$(wg genkey); "
        "pub=$(printf '%s' \"$priv\" | wg pubkey); "
        "printf '%s\\n%s\\n' \"$priv\" \"$pub\""
    ).strip()
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if len(lines) < 2:
        raise CommandError("Failed to generate WireGuard keys")
    return lines[0], lines[1]


def _read_optional_file(executor: object, path: str) -> Optional[str]:
    run = getattr(executor, "run")
    if not callable(run):
        raise CommandError("Executor does not support run")
    try:
        content = executor.run(["cat", path]).strip()
    except CommandError:
        return None
    return content or None


def _append_peer_and_sync(
    executor: object,
    *,
    wg_config_path: str,
    interface_name: str,
    peer_public_key: str,
    peer_ip: str,
    psk: Optional[str],
    peer_name: Optional[str],
) -> None:
    run_shell = getattr(executor, "run_shell")
    if not callable(run_shell):
        raise CommandError("Executor does not support run_shell")
    lines: list[str] = []
    if peer_name:
        lines.append(f"# amnezia-cli: {peer_name}")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {peer_public_key}")
    if psk:
        lines.append(f"PresharedKey = {psk}")
    lines.append(f"AllowedIPs = {peer_ip}/32")
    peer_block = "\n".join(lines) + "\n"
    peer_b64 = base64.b64encode(peer_block.encode("utf-8")).decode("ascii")

    quoted_cfg = shlex.quote(wg_config_path)
    quoted_if = shlex.quote(interface_name)
    script = (
        "set -euo pipefail; "
        "tmp=$(mktemp); "
        f"echo {shlex.quote(peer_b64)} | base64 -d > \"$tmp\"; "
        f"cat \"$tmp\" >> {quoted_cfg}; "
        f"wg syncconf {quoted_if} <(wg-quick strip {quoted_cfg}); "
        "rm -f \"$tmp\""
    )
    executor.run_shell(script)


def _replace_config_and_sync(
    executor: object,
    *,
    wg_config_path: str,
    interface_name: str,
    config_text: str,
) -> None:
    run_shell = getattr(executor, "run_shell")
    if not callable(run_shell):
        raise CommandError("Executor does not support run_shell")
    cfg_b64 = base64.b64encode(config_text.encode("utf-8")).decode("ascii")
    quoted_cfg = shlex.quote(wg_config_path)
    quoted_if = shlex.quote(interface_name)
    script = (
        "set -euo pipefail; "
        "tmp=$(mktemp); "
        f"echo {shlex.quote(cfg_b64)} | base64 -d > \"$tmp\"; "
        f"cat \"$tmp\" > {quoted_cfg}; "
        f"wg syncconf {quoted_if} <(wg-quick strip {quoted_cfg}); "
        "rm -f \"$tmp\""
    )
    executor.run_shell(script)


def _build_client_config(
    *,
    client_private_key: str,
    client_ip: str,
    dns: str,
    server_public_key: str,
    psk: Optional[str],
    endpoint_host: str,
    endpoint_port: int,
    allowed_ips: str,
    keepalive: int,
    awg_params: dict[str, str],
) -> str:
    lines = [
        "[Interface]",
        f"PrivateKey = {client_private_key}",
        f"Address = {client_ip}/32",
        f"DNS = {dns}",
    ]

    for key in AWG_PARAM_KEYS:
        value = awg_params.get(key)
        if value:
            lines.append(f"{key} = {value}")

    lines.extend(
        [
            "",
            "[Peer]",
            f"PublicKey = {server_public_key}",
        ]
    )
    if psk:
        lines.append(f"PresharedKey = {psk}")
    lines.extend(
        [
            f"AllowedIPs = {allowed_ips}",
            f"Endpoint = {endpoint_host}:{endpoint_port}",
            f"PersistentKeepalive = {keepalive}",
            "",
        ]
    )
    return "\n".join(lines)


def _detect_endpoint_host(executor: DockerAwgExecutor, vps_container: Optional[str]) -> str:
    env_host = os.getenv("AMNEZIA_ENDPOINT_HOST", "").strip()
    if env_host:
        return env_host

    scripts = [
        (
            "set -e; "
            "if command -v curl >/dev/null 2>&1; then "
            "for u in https://api.ipify.org https://ifconfig.me; do "
            "ip=$(curl -4fsS --max-time 4 \"$u\" || true); "
            "if [ -n \"$ip\" ]; then echo \"$ip\"; exit 0; fi; "
            "done; "
            "fi; "
            "exit 1"
        ),
        "hostname -I | awk '{print $1}'",
    ]
    for script in scripts:
        try:
            candidate = executor.run_shell(script).strip().split()
            if candidate:
                return candidate[0]
        except CommandError:
            continue
    raise CommandError("Unable to detect endpoint host automatically. Pass --endpoint-host")


def issue_awg_account(
    *,
    awg_container: Optional[str],
    vps_container: Optional[str],
    wg_config_path: str,
    psk_path: str,
    endpoint_host: Optional[str],
    endpoint_port: Optional[int],
    dns: str,
    allowed_ips: str,
    keepalive: int,
    peer_name: Optional[str],
    direct: bool = False,
) -> IssuedAwgAccount:
    context = detect_awg_context(
        wg_config_path=wg_config_path,
        preferred_awg=awg_container,
        preferred_vps=vps_container,
        direct=direct,
    )
    executor = DockerAwgExecutor(awg_container=context.awg_container, vps_container=context.vps_container)
    resolved_wg_config_path = context.wg_config_path
    prefix = executor._prefix()
    resolved_psk_path = _resolve_psk_path_local(
        prefix=prefix,
        container=context.awg_container,
        preferred_psk_path=psk_path,
        resolved_wg_config_path=resolved_wg_config_path,
    )
    cfg_text = executor.run(["cat", resolved_wg_config_path])
    parsed_cfg = parse_wg_config(cfg_text)

    server_iface, network = extract_interface_network(parsed_cfg)
    used_ips = collect_used_client_ips(parsed_cfg, server_iface)
    client_ip = str(allocate_client_ip(network, used_ips))

    interface_name = Path(resolved_wg_config_path).stem
    server_public_key = executor.run_shell(f"wg show {shlex.quote(interface_name)} public-key").strip()
    listen_port_raw = executor.run_shell(f"wg show {shlex.quote(interface_name)} listen-port").strip()
    listen_port = int(listen_port_raw)
    final_endpoint_port = endpoint_port or listen_port
    final_endpoint_host = endpoint_host or _detect_endpoint_host(executor, context.vps_container)

    psk = _read_optional_file(executor, resolved_psk_path)
    client_private_key, client_public_key = _generate_client_keys(executor)

    _append_peer_and_sync(
        executor,
        wg_config_path=resolved_wg_config_path,
        interface_name=interface_name,
        peer_public_key=client_public_key,
        peer_ip=client_ip,
        psk=psk,
        peer_name=peer_name,
    )

    awg_params = {key: value for key, value in parsed_cfg.interface.items() if key in AWG_PARAM_KEYS}
    client_config = _build_client_config(
        client_private_key=client_private_key,
        client_ip=client_ip,
        dns=dns,
        server_public_key=server_public_key,
        psk=psk,
        endpoint_host=final_endpoint_host,
        endpoint_port=final_endpoint_port,
        allowed_ips=allowed_ips,
        keepalive=keepalive,
        awg_params=awg_params,
    )
    token = encode_token(client_config.encode("utf-8"), with_signature=False)

    return IssuedAwgAccount(
        token=token,
        config_text=client_config,
        client_private_key=client_private_key,
        client_public_key=client_public_key,
        client_ip=client_ip,
        endpoint_host=final_endpoint_host,
        endpoint_port=final_endpoint_port,
        awg_container=context.awg_container,
        vps_container=context.vps_container,
        interface_name=interface_name,
    )


def list_awg_accounts(
    *,
    awg_container: Optional[str],
    vps_container: Optional[str],
    wg_config_path: str,
    direct: bool = False,
) -> AwgPeerList:
    context = detect_awg_context(
        wg_config_path=wg_config_path,
        preferred_awg=awg_container,
        preferred_vps=vps_container,
        direct=direct,
    )
    executor = DockerAwgExecutor(awg_container=context.awg_container, vps_container=context.vps_container)
    return _collect_peer_list(
        executor,
        awg_container=context.awg_container,
        vps_container=context.vps_container,
        wg_config_path=context.wg_config_path,
    )


def delete_awg_accounts(
    *,
    awg_container: Optional[str],
    vps_container: Optional[str],
    wg_config_path: str,
    username: str,
    public_key: Optional[str] = None,
    dry_run: bool = False,
    direct: bool = False,
) -> DeletedAwgPeers:
    context = detect_awg_context(
        wg_config_path=wg_config_path,
        preferred_awg=awg_container,
        preferred_vps=vps_container,
        direct=direct,
    )
    executor = DockerAwgExecutor(awg_container=context.awg_container, vps_container=context.vps_container)
    return _delete_awg_peers(
        executor,
        awg_container=context.awg_container,
        vps_container=context.vps_container,
        wg_config_path=context.wg_config_path,
        username=username,
        public_key=public_key,
        dry_run=dry_run,
    )
