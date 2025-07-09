import unittest
from unittest.mock import patch, mock_open, MagicMock
from urllib.parse import urlparse
import sys
import os
import builtins

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import jsSecrets as js

class TestJsSecrets(unittest.TestCase):

    def test_get_js_files_from_html(self):
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
        js_files = [
            "https://cdn.example.com/script.js",
            "//cdn.example.com/script2.js",
            "/static/main.js",
            "local.js"
        ]
        result = js.getFileFullPath(base_url, js_files)
        self.assertIn("https://cdn.example.com/script.js", result)
        self.assertIn("https://cdn.example.com/script2.js", result)
        self.assertIn("https://example.com/static/main.js", result)
        self.assertIn("https://example.com/some/path/local.js", result)

    def test_set_logging_level(self):
        js.set_logging_level(2)
        self.assertEqual(js.logger.level, js.logging.ERROR)
        js.set_logging_level(1)
        self.assertEqual(js.logger.level, js.logging.WARNING)
        js.set_logging_level(0)
        self.assertEqual(js.logger.level, js.logging.INFO)
        js.set_logging_level(99)
        self.assertEqual(js.logger.level, js.logging.DEBUG)

    @patch("builtins.open", new_callable=mock_open, read_data="GET /index.html HTTP/1.1\nHost: example.com\n\n")
    def test_parseRawRequest_get(self, mock_file):
        session, url, method, body = js.parseRawRequest("dummy.txt")
        self.assertEqual(method, "GET")
        self.assertEqual(url, "http://example.com/index.html")
        self.assertEqual(body, "")
        self.assertEqual(session.headers["Host"], "example.com")

    @patch("builtins.open", new_callable=mock_open, read_data="POST /submit HTTP/1.1\nHost: https://secure.com\nContent-Type: application/json\n\n{\"key\":\"value\"}")
    def test_parseRawRequest_post(self, mock_file):
        session, url, method, body = js.parseRawRequest("dummy.txt")
        self.assertEqual(method, "POST")
        self.assertEqual(url, "https://secure.com/submit")
        self.assertEqual(body, "{\"key\":\"value\"}")
        self.assertEqual(session.headers["Content-Type"], "application/json")

    @patch("requests.get")
    def test_seekJsSecrets_finds_secrets(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = 'var token = "abcd1234secret5678"; var api_key = "api_abcdef123456";'
        mock_get.return_value = mock_response

        results = js.seekJsSecrets("https://example.com/file.js")
        self.assertTrue(any("secret" in s[1] or "api_" in s[1] for s in results))

    @patch("requests.get")
    def test_seekJsSecrets_handles_non200(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        results = js.seekJsSecrets("https://example.com/notfound.js")
        self.assertEqual(results, [])

    @patch("requests.get")
    def test_seekJsSecrets_handles_error(self, mock_get):
        mock_get.side_effect = Exception("boom")
        results = js.seekJsSecrets("https://example.com/broken.js")
        self.assertEqual(results, [])

class TestMainFunction(unittest.TestCase):

    @patch("requests.get")
    @patch("sys.argv", ["jsSecrets", "-u", "https://example.com"])
    def test_main_with_url(self, mock_get):
        html = '''
        <script src="main.js"></script>
        <script src="/static/app.js"></script>
        '''
        js_file_content = '''
        var token = "abc123xyz789";
        '''

        mock_get.side_effect = [
            MagicMock(status_code=200, text=html),
            MagicMock(status_code=200, text=js_file_content),
            MagicMock(status_code=200, text="")
        ]

        with patch("builtins.print") as mock_print:
            js.main()
            mock_print.assert_any_call('[https://example.com/static/app.js] (\'token\', \'abc123xyz789\')')

    @patch("builtins.open", new_callable=mock_open, read_data="GET / HTTP/1.1\nHost: example.com\n\n")
    @patch("requests.Session.request")
    @patch("sys.argv", ["jsSecrets", "-r", "dummy.req"])
    def test_main_with_raw_request(self, mock_request, mock_open_file):
        html = '<script src="secrets.js"></script>'
        js_file_content = 'var api_key = "api_987654321";'

        mock_request.side_effect = [
            MagicMock(status_code=200, text=html),
            MagicMock(status_code=200, text=js_file_content)
        ]

        with patch("builtins.print") as mock_print:
            js.main()
            mock_print.assert_any_call('[http://example.com/secrets.js] (\'api_key\', \'api_987654321\')')

    @patch("sys.argv", ["jsSecrets"])
    def test_main_without_args(self):
        with patch("builtins.print") as mock_print:
            js.main()
            mock_print.assert_called()  # help message is printed
            
if __name__ == "__main__":
    unittest.main()
