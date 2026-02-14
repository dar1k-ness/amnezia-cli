import ipaddress
import unittest

from amnezia_cli.selfhosted_awg import (
    _collect_peer_blocks,
    _delete_peer_blocks_from_config,
    _parse_wg_dump,
    allocate_client_ip,
    collect_used_client_ips,
    extract_interface_network,
    parse_wg_config,
    parse_wg_peer_blocks,
)


SAMPLE_CONFIG = """\
[Interface]
Address = 10.8.1.1/24
PrivateKey = server-private
ListenPort = 51820
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 55
S2 = 65
H1 = 12345
H2 = 23456
H3 = 34567
H4 = 45678

[Peer]
PublicKey = peer1
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = peer2
AllowedIPs = 10.8.1.3/32
"""


class SelfHostedAwgTests(unittest.TestCase):
    def test_parse_and_allocate_ip(self) -> None:
        parsed = parse_wg_config(SAMPLE_CONFIG)
        server_iface, network = extract_interface_network(parsed)
        used = collect_used_client_ips(parsed, server_iface)

        next_ip = allocate_client_ip(network, used)
        self.assertEqual(ipaddress.IPv4Address("10.8.1.4"), next_ip)

    def test_extract_interface_ipv4(self) -> None:
        parsed = parse_wg_config(SAMPLE_CONFIG)
        server_iface, network = extract_interface_network(parsed)

        self.assertEqual("10.8.1.1/24", str(server_iface))
        self.assertEqual("10.8.1.0/24", str(network))

    def test_parse_wg_peer_blocks_with_labels(self) -> None:
        config = """\
[Interface]
Address = 10.8.1.1/24

# amnezia-cli: alice
[Peer]
PublicKey = key-a
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = key-b
AllowedIPs = 10.8.1.3/32
"""
        peers = parse_wg_peer_blocks(config)
        self.assertEqual(2, len(peers))
        self.assertEqual("alice", peers[0].get("_label"))
        self.assertEqual("key-a", peers[0].get("PublicKey"))
        self.assertIsNone(peers[1].get("_label"))

    def test_parse_wg_dump_skips_awg_interface_row(self) -> None:
        dump = """\
server-pub\tserver-priv\t33544\t5\t10\t50\t23\t110\t47\t14\th1\th2\th3\th4\t(null)\t(null)\t(null)\t(null)\t(null)\toff
peer-one\tpsk\t(none)\t10.8.1.2/32\t0\t0\t0\toff
peer-two\tpsk\t198.51.100.1:44232\t10.8.1.3/32\t1730000000\t123\t456\t25
"""
        parsed = _parse_wg_dump(dump)

        self.assertNotIn("server-pub", parsed)
        self.assertEqual("10.8.1.2/32", parsed["peer-one"]["allowed_ips"])
        self.assertEqual("198.51.100.1:44232", parsed["peer-two"]["endpoint"])

    def test_collect_peer_blocks_for_deletion(self) -> None:
        config = """\
[Interface]
Address = 10.8.1.1/24

# amnezia-cli: dark
[Peer]
PublicKey = key-dark-1
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = key-plain
AllowedIPs = 10.8.1.3/32

# amnezia-cli: dark
[Peer]
PublicKey = key-dark-2
AllowedIPs = 10.8.1.4/32
"""
        blocks = _collect_peer_blocks(config)
        self.assertEqual(3, len(blocks))
        self.assertEqual("dark", blocks[0].label)
        self.assertIsNone(blocks[1].label)
        self.assertEqual("dark", blocks[2].label)

    def test_delete_peer_blocks_from_config(self) -> None:
        config = """\
[Interface]
Address = 10.8.1.1/24

# amnezia-cli: dark
[Peer]
PublicKey = key-dark-1
AllowedIPs = 10.8.1.2/32

# amnezia-cli: alice
[Peer]
PublicKey = key-alice
AllowedIPs = 10.8.1.3/32
"""
        blocks = _collect_peer_blocks(config)
        to_delete = [block for block in blocks if block.label == "dark"]
        updated = _delete_peer_blocks_from_config(config, to_delete)
        peers = parse_wg_peer_blocks(updated)

        self.assertEqual(1, len(peers))
        self.assertEqual("alice", peers[0].get("_label"))
        self.assertEqual("key-alice", peers[0].get("PublicKey"))


if __name__ == "__main__":
    unittest.main()
