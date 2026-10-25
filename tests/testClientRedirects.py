"""McritClient keeps its token and request bodies to the server it was given, across redirects.

requests drops an Authorization header on a redirect to another host, but not MCRIT's `apitoken`
header, and it resends the body of a 307 or 308. A redirect from the configured server - or from
whatever answers in its place - handed both to any host it named.
"""

import http.server
import json
import threading
import unittest
from typing import Any, Dict, List, Optional

from mcrit.client.McritClient import McritClient


class _RecordingServer(http.server.ThreadingHTTPServer):
    """Answers every request with 200, or with the redirect it was told to give; records what it got."""

    def __init__(self, host: str):
        super().__init__((host, 0), _Recorder)
        self.received: List[Dict[str, Any]] = []
        # redirect every request to this origin, keeping the path
        self.redirect_to: Optional[str] = None
        self.redirect_status = 307
        # redirect each request once to its own path + "/again" on this server
        self.redirect_to_itself = False

    @property
    def url(self) -> str:
        return f"http://{self.server_address[0]}:{self.server_address[1]}"


class _Recorder(http.server.BaseHTTPRequestHandler):
    server: _RecordingServer

    def _answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.server.received.append({"path": self.path, "method": self.command, "headers": dict(self.headers), "body": self.rfile.read(length)})
        location = None
        if self.server.redirect_to:
            location = self.server.redirect_to + self.path
        elif self.server.redirect_to_itself and not self.path.endswith("/again"):
            location = self.server.url + self.path + "/again"
        if location:
            self.send_response(self.server.redirect_status)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps({"status": "successful", "data": {"version": "test"}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = _answer

    def log_message(self, format, *args):
        pass


class ClientRedirectTest(unittest.TestCase):
    def _server(self, host):
        server = _RecordingServer(host)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def setUp(self):
        # two origins: the same machine under two host names, on two ports
        self.configured = self._server("127.0.0.1")
        self.elsewhere = self._server("localhost")
        self.elsewhere_url = f"http://localhost:{self.elsewhere.server_address[1]}"
        self.client = McritClient(mcrit_server=self.configured.url, apitoken="secret-token", username="analyst")

    def _forwarded_headers(self):
        self.assertEqual(1, len(self.elsewhere.received))
        return {name.lower() for name in self.elsewhere.received[0]["headers"]}

    def test_a_redirect_to_another_origin_gets_neither_the_token_nor_the_body(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                self.configured.received.clear()
                self.elsewhere.received.clear()
                self.configured.redirect_to, self.configured.redirect_status = self.elsewhere_url, status
                self.client.addBinarySample(b"MZ binary contents", filename="sample.exe", family="family", version="1")
                self.assertEqual("secret-token", self.configured.received[0]["headers"].get("apitoken"))
                self.assertEqual(b"MZ binary contents", self.configured.received[0]["body"])
                self.assertNotIn("apitoken", self._forwarded_headers())
                self.assertEqual(b"", self.elsewhere.received[0]["body"])

    def test_a_redirect_within_the_origin_keeps_both(self):
        """A server behind a proxy that redirects /x to /x/ still gets what it needs."""
        self.configured.redirect_to_itself = True
        self.client.addBinarySample(b"MZ binary contents", filename="sample.exe", family="family", version="1")
        self.assertEqual(2, len(self.configured.received))
        again = self.configured.received[1]
        self.assertTrue(again["path"].endswith("/again"))
        self.assertEqual("secret-token", again["headers"].get("apitoken"))
        self.assertEqual(b"MZ binary contents", again["body"])

    def test_every_request_redirected_elsewhere_drops_the_token(self):
        """Including the download of a sample binary, which went out with requests.get of its own."""
        self.configured.redirect_to = self.elsewhere_url
        for name, call in (("getVersion", self.client.getVersion), ("getSampleBinary", lambda: self.client.getSampleBinary(1))):
            with self.subTest(name):
                self.elsewhere.received.clear()
                call()
                self.assertNotIn("apitoken", self._forwarded_headers())


if __name__ == "__main__":
    unittest.main()
