import contextlib  # noqa: E402
import os  # noqa: E402
import unittest  # noqa: E402
from io import StringIO  # noqa: E402
from unittest.mock import patch  # noqa: E402
from urllib.error import URLError

from tinytg import request, Response


class RequestTestCase(unittest.TestCase):
    def test_cannot_provide_json_and_data(self):
        with self.assertRaises(Exception):
            request("POST",
                "https://httpbingo.org/post",
                json={"name": "Brenton"},
                data="This is some form data",
            )

    def test_should_fail_if_json_or_data_and_not_p_method(self):
        with self.assertRaises(Exception):
            request("GET", "https://httpbingo.org/post", json={"name": "Brenton"})

        with self.assertRaises(Exception):
            request("HEAD", "https://httpbingo.org/post", json={"name": "Brenton"})

    def test_should_set_content_type_for_json_request(self):
        response = request("POST","https://httpbingo.org/post", json={"name": "Brenton"})
        self.assertEqual(response.request.headers["Content-type"], "application/json")

    def test_should_work(self):
        response = request("GET", "https://httpbingo.org/get")
        self.assertEqual(response.status, 200)

    def test_should_create_url_from_params(self):
        response = request("GET",
            "https://httpbingo.org/get",
            params={"name": "brenton", "library": "tiny-request"},
        )
        self.assertEqual(response.url, "https://httpbingo.org/get?name=brenton&library=tiny-request")

    def test_should_return_headers(self):
        response = request("GET","https://httpbingo.org/response-headers", params={"Test-Header": "value"})
        self.assertEqual(response.headers["test-header"], "value")

    def test_should_populate_json(self):
        response = request("GET", "https://httpbingo.org/json")
        self.assertTrue("slideshow" in response.json)

    def test_should_return_response_for_404(self):
        response = request("GET", "https://httpbingo.org/404")
        self.assertEqual(response.status, 404)
        self.assertTrue("application/json" in response.headers["content-type"])

    def test_should_fail_with_bad_ssl(self):
        with self.assertRaises(URLError):
            request("GET", "https://expired.badssl.com/")

    def test_should_load_bad_ssl_with_verify_false(self):
        response = request("GET","https://expired.badssl.com/", verify=False)
        self.assertEqual(response.status, 200)

    def test_should_form_encode_non_json_post_requests(self):
        response = request("POST","https://httpbingo.org/post", data={"name": "test-user"})
        self.assertEqual(response.json["form"]["name"], ["test-user"])

    def test_should_follow_redirect(self):
        response = request("GET",
            "https://httpbingo.org/redirect-to",
            params={"url": "https://example.org/"},
        )
        self.assertEqual(response.url, "https://example.org/")
        self.assertEqual(response.status, 200)

    def test_should_not_follow_redirect_if_redirect_false(self):
        response = request("GET",
            "https://httpbingo.org/redirect-to",
            params={"url": "https://example.org/"},
            redirect=False,
        )
        self.assertEqual(response.status, 302)

    def test_cookies(self):
        response = request('GET',
            "https://httpbingo.org/cookies/set",
            params={"cookie": "test"},
            redirect=False,
        )
        response = request('GET',"https://httpbingo.org/cookies", cookiejar=response.cookiejar)
        self.assertEqual(response.json["cookie"], "test")

    def test_basic_auth(self):
        response = request("GET", "http://httpbingo.org/basic-auth/user/passwd", basic_auth=("user", "passwd"))
        self.assertEqual(response.json["authorized"], True)

    def test_should_handle_gzip(self):
        response = request("GET", "http://httpbingo.org/gzip", headers={"Accept-Encoding": "gzip"})
        self.assertEqual(response.json["gzipped"], True)

    def test_should_handle_gzip_error(self):
        response = request("GET","http://httpbingo.org/status/418", headers={"Accept-Encoding": "gzip"})
        self.assertEqual(response.content, b"I'm a teapot!")

    def test_should_timeout(self):
        import socket

        with self.assertRaises((TimeoutError, socket.timeout)):
            request("GET", "http://httpbingo.org/delay/3", timeout=1)

    def test_should_handle_head_requests(self):
        response = request("HEAD", "http://httpbingo.org/head")
        self.assertTrue(response.content == b"")

    def test_should_post_data_string(self):
        response = request("POST",
            "https://ntfy.sh/thttp-test-ntfy",
            data="The thttp test suite was executed!",
        )
        self.assertTrue(response.json["topic"] == "thttp-test-ntfy")


    def test_thttp_with_mocked_response(self):
        mocked_response = Response(None, None, {"response": "mocked"}, 200, None, None, None)

        with patch("tinytg.request", side_effect=[mocked_response]):
            response = request("GET", "https://example.org")
            self.assertEqual("mocked", response.json["response"])

    def test_upload_single_file(self):
        token = os.environ.get("MEDIAPUB_TOKEN")
        url = os.environ.get("MEDIAPUB_URL")

        if not token or not url:
            self.skipTest("Skipping media upload test because environment variables are not available")

        for fn in ["test-image.png", "LICENSE.md"]:
            with open(fn, "rb" if fn.endswith("png") else "r") as f:
                response = request(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    files={"file": f},
                    method="POST",
                )

            self.assertEqual(response.status, 201)
            self.assertTrue("location" in response.headers)