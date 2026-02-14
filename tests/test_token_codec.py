import unittest

from amnezia_cli.token_codec import decode_token, encode_token


class TokenCodecTests(unittest.TestCase):
    def test_round_trip_default_mode(self) -> None:
        payload = b'{"name":"test","value":1}'
        token = encode_token(payload)
        decoded = decode_token(token)

        self.assertEqual(payload, decoded.payload)
        self.assertFalse(decoded.used_signature)

    def test_round_trip_signature_mode(self) -> None:
        payload = b'{"name":"signed"}'
        token = encode_token(payload, with_signature=True)
        decoded = decode_token(token)

        self.assertEqual(payload, decoded.payload)
        self.assertTrue(decoded.used_signature)

    def test_decode_without_prefix(self) -> None:
        payload = b'{"name":"short"}'
        token = encode_token(payload)
        decoded = decode_token(token.replace("vpn://", "", 1))
        self.assertEqual(payload, decoded.payload)


if __name__ == "__main__":
    unittest.main()

