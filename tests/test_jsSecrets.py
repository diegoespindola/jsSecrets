import unittest
from unittest.mock import patch, mock_open, MagicMock
from urllib.parse import urlparse

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import jsSecrets as js

class TestJsSecrets(unittest.TestCase):

    def test_getJsFilesFromHTML(self):
        html = '''
        <script src="main.js"></script>
        <script src="/static/js/app.js"></script>
        <meta content="https://example.com/script.js">
        <link href="https://cdn.example.com/script2.js">
        '''
        result = js.get_js_files_from_html(html)
        self.assertIn("main.js", result)
        self.assertIn("/static/js/app.js", result)
        self.assertIn("https://example.com/script.js", result)
        self.assertIn("https://cdn.example.com/script2.js", result)

    def test_getFileFullPath(self):
        base_url = urlparse("https://example.com/some/path/")
        jsFiles = [
            "https://cdn.example.com/script.js",
            "//cdn.example.com/script2.js",
            "/static/main.js",
            "local.js"
        ]
        result = js.getFileFullPath(base_url, jsFiles)
        self.assertIn("https://cdn.example.com/script.js", result)
        self.assertIn("https://cdn.example.com/script2.js", result)
        self.assertIn("https://example.com/static/main.js", result)
        self.assertIn("https://example.com/some/path/local.js", result)

    @patch("builtins.open", new_callable=mock_open, read_data="GET /index.html HTTP/1.1\nHost: example.com\n\n")
    def test_parseRawRequest_get(self, mock_file):
        session, url, method, body = js.parseRawRequest("dummy.txt")
        self.assertEqual(method, "GET")
        self.assertEqual(url, "http://example.com/index.html")
        self.assertEqual(body, "")
        self.assertEqual(session.headers["Host"], "example.com")

    @patch("requests.get")
    def test_seekJsSecrets_finds_secrets(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = 'var token = "abcd1234secret5678"; var api_key = "api_abcdef123456";'
        mock_get.return_value = mock_response

        results = js.seekJsSecrets("https://example.com/file.js")
        self.assertTrue(any("secret" in s[1] or "api_" in s[1] for s in results))

    @patch("requests.get")
    def test_seekJsSecrets_handles_error(self, mock_get):
        mock_get.side_effect = Exception("boom")
        results = js.seekJsSecrets("https://example.com/broken.js")
        self.assertEqual(results, [])

if __name__ == "__main__":
    unittest.main()
