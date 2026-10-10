"""The local web UI: same passes in a browser, plus the token gate.

The gate matters because this server can start dynamic instrumentation: bound to
a real interface it is a network service, so it refuses to listen without a
token, and with one it answers ``401`` to anything that does not present it --
including a page whose fetch() calls would otherwise reach the API.

The tests drive the handler class the way :func:`revlab.webui.serve` does, which
keeps the server's lifetime under the test's control.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from revlab import webui
from revlab.config import load_config


def _config_file(root: Path) -> Path:
    path = root / "revlab.toml"
    path.write_text(
        f'[workspace]\nroot = "{(root / "workspaces").as_posix()}"\n'
        '[scope]\nauthorised = ["demo.apk"]\n',
        encoding="utf-8",
    )
    return path


class ServeGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = load_config(_config_file(self.root))
        self.servers: list[ThreadingHTTPServer] = []

    def tearDown(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.tmp.cleanup()

    def _serve(self, token: str | None) -> str:
        handler = type("BoundApi", (webui.Api,), {"config": self.config, "token": token})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{server.server_address[1]}"

    @staticmethod
    def _get(url: str) -> tuple[int, str]:
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                return response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read().decode("utf-8")

    def test_without_a_token_the_loopback_ui_answers(self) -> None:
        status, body = self._get(self._serve(None) + "/")
        self.assertEqual(status, 200)
        self.assertIn("<h1>RevLab</h1>", body)
        self.assertIn("window.REVLAB_TOKEN=null", body)

    def test_with_a_token_everything_needs_it(self) -> None:
        base = self._serve("s3cret")

        status, body = self._get(base + "/")
        self.assertEqual(status, 401)
        self.assertIn("unauthorised", body)

        status, body = self._get(base + "/api/status")
        self.assertEqual(status, 401)

        status, body = self._get(base + "/?t=s3cret")
        self.assertEqual(status, 200)
        self.assertIn('window.REVLAB_TOKEN="s3cret"', body)   # handed to the page

        status, body = self._get(base + "/api/status?t=s3cret")
        self.assertEqual(status, 200)
        self.assertIn("authorised", json.loads(body))

    def test_the_header_works_too(self) -> None:
        base = self._serve("hdr-token")
        request = urllib.request.Request(base + "/api/sessions",
                                         headers={"X-RevLab-Token": "hdr-token"})
        with urllib.request.urlopen(request, timeout=10) as response:
            self.assertEqual(response.status, 200)
            self.assertIn("sessions", json.loads(response.read().decode("utf-8")))

    def test_a_wrong_token_is_not_accepted(self) -> None:
        base = self._serve("right")
        status, _ = self._get(base + "/?t=wrong")
        self.assertEqual(status, 401)

    def test_binding_a_real_interface_without_a_token_is_refused(self) -> None:
        # No socket is opened: the refusal happens before the bind.
        self.assertEqual(webui.serve(self.config, host="0.0.0.0", token=None), 2)
        self.assertEqual(webui.serve(self.config, host="192.168.0.1", token=""), 2)


if __name__ == "__main__":
    unittest.main()
