import unittest
from unittest.mock import patch, MagicMock
from core.cli.app import build_parser
from core.cli.commands.serve import run_serve


class TestCLIServeCommands(unittest.TestCase):
    def test_parser_supports_view_command_and_open_flag(self):
        parser = build_parser()
        args = parser.parse_args(["view", "--open", "--port", "5055"])
        self.assertEqual(args.command, "view")
        self.assertTrue(args.open)
        self.assertEqual(args.port, 5055)

    @patch("webbrowser.open_new_tab")
    @patch("web_ui.app.run")
    def test_run_serve_with_open_flag_launches_browser(self, mock_flask_run, mock_browser_open):
        mock_args = MagicMock(host="127.0.0.1", port=5000, debug=False, no_color=True, open=True, _open_delay=0)
        res = run_serve(mock_args)
        self.assertEqual(res, 0)
        mock_browser_open.assert_called_once_with("http://127.0.0.1:5000")
        mock_flask_run.assert_called_once()
