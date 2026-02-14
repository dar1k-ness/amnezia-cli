import argparse
import io
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from amnezia_cli import cli


class CliUserParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = cli.build_parser()

    def test_user_add_parser(self) -> None:
        args = self.parser.parse_args(["user", "add", "alice"])
        self.assertIs(args.func, cli.cmd_user_add)
        self.assertEqual("alice", args.username)

    def test_user_list_parser(self) -> None:
        args = self.parser.parse_args(["user", "list"])
        self.assertIs(args.func, cli.cmd_user_list)

    def test_user_show_parser(self) -> None:
        args = self.parser.parse_args(["user", "show", "alice"])
        self.assertIs(args.func, cli.cmd_user_show)
        self.assertEqual("alice", args.username)

    def test_user_del_alias_rm_parser(self) -> None:
        args = self.parser.parse_args(["user", "rm", "alice"])
        self.assertIs(args.func, cli.cmd_user_del)
        self.assertEqual("alice", args.username)

    def test_selfhosted_server_command_removed(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.parser.parse_args(["selfhosted", "server", "show"])


class CliUserCommandTests(unittest.TestCase):
    @patch("amnezia_cli.cli.cmd_selfhosted_awg_add")
    def test_cmd_user_add_sets_direct_by_default(self, mock_cmd: object) -> None:
        mock_cmd.return_value = 0
        args = argparse.Namespace(direct=False, vps_container=None)

        rc = cli.cmd_user_add(args)

        self.assertEqual(0, rc)
        self.assertTrue(args.direct)
        mock_cmd.assert_called_once_with(args)

    @patch("amnezia_cli.cli.cmd_selfhosted_awg_list")
    def test_cmd_user_list_keeps_direct_when_vps_container_is_set(self, mock_cmd: object) -> None:
        mock_cmd.return_value = 0
        args = argparse.Namespace(direct=False, vps_container="nested-vps")

        rc = cli.cmd_user_list(args)

        self.assertEqual(0, rc)
        self.assertFalse(args.direct)
        mock_cmd.assert_called_once_with(args)


if __name__ == "__main__":
    unittest.main()
