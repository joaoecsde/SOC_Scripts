"""Tests for the Flask routes in web/app.py.

Run from the web folder:
    python3 -m unittest tests.test_app -v
"""
import io
import os
import sys
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import app as webapp                             # noqa: E402
import jobs                                      # noqa: E402
import samples                                   # noqa: E402

SECRET = "KEYSECRET1234567890abcdef"


class ExitSignalTests(unittest.TestCase):
    def installed(self, fake_signal):
        with mock.patch.object(webapp, "signal", fake_signal):
            webapp.install_exit_handlers()
        return [call.args[0] for call in fake_signal.signal.call_args_list]

    def test_windows_has_no_sighup(self):
        fake = mock.Mock(spec=["SIGTERM", "SIGBREAK", "signal"])
        self.assertEqual(self.installed(fake), [fake.SIGTERM, fake.SIGBREAK])

    def test_unix_has_no_sigbreak(self):
        fake = mock.Mock(spec=["SIGTERM", "SIGHUP", "signal"])
        self.assertEqual(self.installed(fake), [fake.SIGTERM, fake.SIGHUP])


class AppTests(unittest.TestCase):
    def setUp(self):
        self.store = jobs.JobStore()
        self.app = webapp.create_app(self.store)
        self.app.testing = True
        self.client = self.app.test_client()

    def wait(self, response):
        """Follow a 303 to the job page and wait for the job to finish."""
        self.assertEqual(response.status_code, 303)
        path = response.headers["Location"]
        job = self.store.get(path.rsplit("/", 1)[-1])
        job._thread.join(timeout=10)
        return job, path

    def post_file(self, tool, data, name, content, **extra):
        fields = {"file": (io.BytesIO(content), name)}
        fields.update(extra)
        return self.client.post(f"/analyse/{tool}", data=fields,
                                content_type="multipart/form-data")

    def test_index_has_three_tabs(self):
        body = self.client.get("/").get_data(as_text=True)
        for text in ("Investigation Tools", "Email", "IP / Hash", "PDF"):
            self.assertIn(text, body)

    def test_email_flow_offline(self):
        job, path = self.wait(self.post_file("email", None, "evil.eml", samples.phishing_eml()))
        page = self.client.get(path)
        self.assertEqual(page.status_code, 200)
        self.assertIn("HIGH", page.get_data(as_text=True))
        resp = self.client.get(path + "/json")
        self.assertEqual(resp.mimetype, "application/json")
        self.assertEqual(resp.get_json()["source"], "evil.eml")

    def test_missing_file(self):
        resp = self.client.post("/analyse/email", data={})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Choose a file to analyse.", resp.get_data(as_text=True))

    def test_upload_too_large(self):
        self.app.config["MAX_CONTENT_LENGTH"] = 10
        resp = self.post_file("email", None, "a.eml", b"x" * 100)
        self.assertEqual(resp.status_code, 413)
        self.assertIn(f"larger than {webapp.MAX_UPLOAD_MB} MB", resp.get_data(as_text=True))

    def test_online_without_keys(self):
        resp = self.post_file("email", None, "a.eml", samples.phishing_eml(), online="on")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("AbuseIPDB key", resp.get_data(as_text=True))

    def test_ioc_requires_needed_key(self):
        resp = self.client.post("/analyse/ioc", data={"indicators": "8.8.8.8"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Add an AbuseIPDB key", resp.get_data(as_text=True))

    def test_ioc_empty(self):
        resp = self.client.post("/analyse/ioc", data={"indicators": "  "})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Paste at least one IP or hash.", resp.get_data(as_text=True))

    def test_ioc_private_ip_needs_no_key(self):
        resp = self.client.post("/analyse/ioc", data={"indicators": "10.0.0.1"})
        self.wait(resp)

    def test_max_age_range(self):
        resp = self.client.post("/analyse/ioc", data={"indicators": "10.0.0.1", "max_age": "0"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("between 1 and 365", resp.get_data(as_text=True))

    def test_bad_delay(self):
        resp = self.client.post("/analyse/ioc", data={"indicators": "10.0.0.1", "delay": "-1"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Delay must be a number of seconds from 0 to 300.", resp.get_data(as_text=True))

    def test_delay_above_cap(self):
        resp = self.client.post("/analyse/ioc", data={"indicators": "10.0.0.1", "delay": "301"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("from 0 to 300", resp.get_data(as_text=True))

    def test_email_delay_ignored_when_offline(self):
        resp = self.post_file("email", None, "a.eml", samples.phishing_eml(), delay="abc")
        self.wait(resp)

    def test_email_delay_checked_when_online(self):
        resp = self.post_file("email", None, "a.eml", samples.phishing_eml(), online="on",
                              abuseipdb_key="k", delay="999")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("from 0 to 300", resp.get_data(as_text=True))

    def test_ioc_placeholder_key_rejected(self):
        resp = self.client.post("/analyse/ioc", data={
            "indicators": "8.8.8.8", "abuseipdb_key": "your_key_here"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Add an AbuseIPDB key", resp.get_data(as_text=True))

    def test_unknown_job_json_and_payloads_show_expired_page(self):
        for suffix in ("/json", "/payloads"):
            resp = self.client.get("/job/nope" + suffix)
            self.assertEqual(resp.status_code, 404)
            self.assertIn("expired", resp.get_data(as_text=True))

    def test_pdf_extract_leaves_only_zip(self):
        job, _ = self.wait(self.post_file("pdf", None, "a.pdf", samples.js_pdf(), extract="on"))
        self.assertEqual([p.name for p in job.workdir.iterdir()], ["payloads.zip"])

    def test_status_endpoint_has_no_keys(self):
        fake = {"abuseipdb_score": 5}
        with mock.patch("threat_lookup.lookup_ip", return_value=fake):
            resp = self.client.post("/analyse/ioc", data={
                "indicators": "8.8.8.8", "abuseipdb_key": SECRET})
            job, path = self.wait(resp)
        self.assertNotIn("KEYSECRET", self.client.get(path + "/status").get_data(as_text=True))
        self.assertNotIn("KEYSECRET", self.client.get(path + "/json").get_data(as_text=True))
        self.assertNotIn("KEYSECRET", self.client.get(path).get_data(as_text=True))

    def test_validation_error_does_not_echo_keys(self):
        resp = self.client.post("/analyse/ioc", data={
            "indicators": "", "abuseipdb_key": SECRET})
        self.assertEqual(resp.status_code, 400)
        self.assertNotIn("KEYSECRET", resp.get_data(as_text=True))

    def test_pdf_extract_download(self):
        job, path = self.wait(self.post_file("pdf", None, "a.pdf", samples.js_pdf(), extract="on"))
        with self.client.get(path + "/payloads") as resp:
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.mimetype, "application/zip")
        body = self.client.get(path + "/json").get_data(as_text=True)
        self.assertNotIn(str(job.workdir), body)
        self.assertNotIn("soc-web-", body)

    def test_payloads_404_without_zip(self):
        job, path = self.wait(self.post_file("pdf", None, "a.pdf", samples.js_pdf()))
        self.assertEqual(self.client.get(path + "/payloads").status_code, 404)

    def test_msg_upload_shows_plain_error(self):
        job, path = self.wait(self.post_file("email", None, "a.msg", samples.msg_file()))
        body = self.client.get(path).get_data(as_text=True)
        self.assertIn(".eml", body)
        self.assertNotIn("Traceback", body)

    def test_unknown_job_404_page(self):
        resp = self.client.get("/job/nope")
        self.assertEqual(resp.status_code, 404)
        self.assertIn("expired", resp.get_data(as_text=True))
        self.assertEqual(self.client.get("/job/nope/status").status_code, 404)

    def test_uploads_removed_after_job(self):
        job, _ = self.wait(self.post_file("email", None, "evil.eml", samples.phishing_eml()))
        self.assertFalse(job.workdir.exists())

    def test_result_escapes_html(self):
        job, path = self.wait(self.post_file("email", None, "evil.eml", samples.phishing_eml()))
        body = self.client.get(path).get_data(as_text=True)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", body)
        self.assertNotIn("<script>alert(1)", body)

    def test_result_defangs_iocs(self):
        job, path = self.wait(self.post_file("email", None, "evil.eml", samples.phishing_eml()))
        body = self.client.get(path).get_data(as_text=True)
        self.assertIn("45[.]9[.]148[.]12", body)
        self.assertNotIn("http://45.9.148.12", body)

    def test_index_has_feature_grids(self):
        body = self.client.get("/").get_data(as_text=True)
        for text in ("What the email analysis checks", "Sender authentication",
                     "Who owns the IP", "Fully offline"):
            self.assertIn(text, body)

    def test_progress_page_shows_counts(self):
        release = threading.Event()

        def work(job):
            self.store.progress_callback(job)(3, 5, "Checking things")
            release.wait(10)
            return []

        job = self.store.start("ioc", work)
        try:
            for _ in range(100):
                if self.store.status(job)["done"] == 3:
                    break
                time.sleep(0.01)
            body = self.client.get(f"/job/{job.id}").get_data(as_text=True)
            self.assertIn("3 of 5 done", body)
        finally:
            release.set()
            job._thread.join(timeout=10)

    def test_ioc_result_card_fields(self):
        fake = {"ip": "8.8.8.8", "abuse_score": 90, "total_reports": 12, "distinct_users": 4,
                "country": "NL", "isp": "Evil ISP", "domain": "evil.example",
                "is_tor": False, "is_whitelisted": False, "last_reported": None,
                "usage_type": "Data Center"}
        with mock.patch("threat_lookup.lookup_ip", return_value=fake):
            resp = self.client.post("/analyse/ioc", data={
                "indicators": "8.8.8.8", "abuseipdb_key": SECRET})
            job, path = self.wait(resp)
        body = self.client.get(path).get_data(as_text=True)
        self.assertIn("Evil ISP", body)
        self.assertIn("90", body)


if __name__ == "__main__":
    unittest.main()
