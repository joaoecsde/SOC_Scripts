"""Tests for the Flask routes in web/app.py.

Run from the web folder:
    python3 -m unittest tests.test_app -v
"""
import io
import os
import re
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

    def csrf_token(self):
        """Read the token from the landing page, as a browser would."""
        page = self.client.get("/").get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)

    def post(self, path, data=None, **kwargs):
        fields = dict(data or {}, csrf_token=self.csrf_token())
        return self.client.post(path, data=fields, **kwargs)

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
        return self.post(f"/analyse/{tool}", data=fields,
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
        resp = self.post("/analyse/email", data={})
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
        resp = self.post("/analyse/ioc", data={"indicators": "8.8.8.8"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Add an AbuseIPDB key", resp.get_data(as_text=True))

    def test_ioc_empty(self):
        resp = self.post("/analyse/ioc", data={"indicators": "  "})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Paste at least one IP or hash.", resp.get_data(as_text=True))

    def test_ioc_private_ip_needs_no_key(self):
        resp = self.post("/analyse/ioc", data={"indicators": "10.0.0.1"})
        self.wait(resp)

    def test_max_age_range(self):
        resp = self.post("/analyse/ioc", data={"indicators": "10.0.0.1", "max_age": "0"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("between 1 and 365", resp.get_data(as_text=True))

    def test_bad_delay(self):
        resp = self.post("/analyse/ioc", data={"indicators": "10.0.0.1", "delay": "-1"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Delay must be a number of seconds from 0 to 300.", resp.get_data(as_text=True))

    def test_delay_above_cap(self):
        resp = self.post("/analyse/ioc", data={"indicators": "10.0.0.1", "delay": "301"})
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
        resp = self.post("/analyse/ioc", data={
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
            resp = self.post("/analyse/ioc", data={
                "indicators": "8.8.8.8", "abuseipdb_key": SECRET})
            job, path = self.wait(resp)
        self.assertNotIn("KEYSECRET", self.client.get(path + "/status").get_data(as_text=True))
        self.assertNotIn("KEYSECRET", self.client.get(path + "/json").get_data(as_text=True))
        self.assertNotIn("KEYSECRET", self.client.get(path).get_data(as_text=True))

    def test_validation_error_does_not_echo_keys(self):
        resp = self.post("/analyse/ioc", data={
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
        resp = self.post_file("email", None, "a.msg", samples.msg_file())
        self.assertEqual(resp.status_code, 400)
        body = resp.get_data(as_text=True)
        self.assertIn("Outlook", body)
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
            resp = self.post("/analyse/ioc", data={
                "indicators": "8.8.8.8", "abuseipdb_key": SECRET})
            job, path = self.wait(resp)
        body = self.client.get(path).get_data(as_text=True)
        self.assertIn("Evil ISP", body)
        self.assertIn("90", body)

    def assert_refused(self, resp, status=400):
        """The request was answered with an error and no job was started."""
        self.assertEqual(resp.status_code, status)
        self.assertEqual(self.store._jobs, {})

    def test_ioc_refuses_anything_but_ips_and_hashes(self):
        for line in ("' OR 1=1--", "; rm -rf /", "<script>alert(1)</script>", "evil[.]com",
                     "hxxp://evil[.]com/x", "$(whoami)", "44d88612fea8a8f36de82e1278abb02",
                     "2606:4700:4700::1111%' OR 1=1--"):
            with self.subTest(line=line):
                resp = self.post("/analyse/ioc", data={"indicators": line})
                self.assert_refused(resp)
                self.assertIn("Line 1 ", resp.get_data(as_text=True))

    def test_ioc_refused_input_is_not_rendered(self):
        resp = self.post("/analyse/ioc", data={"indicators": "10.0.0.1\nMARKER' OR 1=1--"})
        self.assert_refused(resp)
        body = resp.get_data(as_text=True)
        self.assertNotIn("MARKER", body)
        self.assertNotIn("10.0.0.1", body)

    def test_ioc_one_bad_line_refuses_the_whole_list(self):
        text = "10.0.0.1\nnope\n\n# a comment\nalso nope"
        resp = self.post("/analyse/ioc", data={"indicators": text})
        self.assert_refused(resp)
        self.assertIn("Lines 2, 5 ", resp.get_data(as_text=True))

    def test_ioc_accepts_defanged_ip_and_comments(self):
        resp = self.post("/analyse/ioc", data={"indicators": "# note\n10[.]0[.]0[.]1"})
        self.wait(resp)

    def test_pdf_refuses_wrong_files(self):
        pdf = samples.js_pdf()
        for name, content in (("evil.exe", pdf), ("a.txt", pdf), ("noextension", pdf),
                              ("x.pdf", b"#!/bin/sh\nrm -rf /\n# %PDF-\n"),
                              ("mz.pdf", b"MZ\x90\x00" + b"A" * 50 + b"%PDF-1.4\n"),
                              ("elf.pdf", b"\x7fELF" + b"A" * 50 + b"%PDF-1.4\n"),
                              ("notes.pdf", samples.not_pdf()),
                              ("late.pdf", b"A" * 1024 + pdf)):
            with self.subTest(name=name):
                self.assert_refused(self.post_file("pdf", None, name, content))

    def test_pdf_accepts_junk_before_header_within_window(self):
        for name, content in (("a.pdf", b"junk\n" + samples.js_pdf()),
                              ("A.PDF", b"A" * 1019 + samples.js_pdf())):
            with self.subTest(name=name):
                job, _ = self.wait(self.post_file("pdf", None, name, content))
                self.assertEqual(job.status, "done")

    def test_email_refuses_wrong_files(self):
        for name, content in (("evil.exe", samples.phishing_eml()),
                              ("x.sh", b"From: a@b.example\n\nrm -rf /\n"),
                              ("a.pdf", samples.phishing_eml()),
                              ("subject.eml", b"Subject: only this\n\nhello\n"),
                              ("date.txt", b"Date: Mon, 1 Jan 2024 10:00:00 +0000\n"),
                              ("text.txt", b"just some text\n"),
                              ("doc.eml", b"%PDF-1.4\nFrom: a@b.example\n")):
            with self.subTest(name=name):
                self.assert_refused(self.post_file("email", None, name, content))

    def test_email_accepts_eml_and_header_text(self):
        for name, content in (("a.EML", samples.phishing_eml()),
                              ("from.txt", b"From: a@b.example\n"),
                              ("relay.txt", b"Received: from a by b\n")):
            with self.subTest(name=name):
                job, _ = self.wait(self.post_file("email", None, name, content))
                self.assertEqual(job.status, "done")

    def test_email_with_unparsable_headers_gets_a_plain_refusal(self):
        nested = b"".join(b"Content-Type: multipart/mixed; boundary=b%d\n\n--b%d\n" % (i, i)
                          for i in range(1000))
        for name, content in (("group.eml", b"From: group:; \nSubject: x\n"),
                              ("word.eml", b"From: =?utf-8?B?!!!?=\n"),
                              ("angle.eml", b"From: <\n"),
                              ("nested.eml", b"From: a@b.example\n" + nested)):
            with self.subTest(name=name):
                resp = self.post_file("email", None, name, content)
                if resp.status_code == 303:
                    job, _ = self.wait(resp)
                    self.assertIn(job.status, ("done", "error"))
                else:
                    self.assertEqual(resp.status_code, 400)

    def test_email_with_malformed_from_is_still_analysed(self):
        job, _ = self.wait(self.post_file("email", None, "a.eml",
                                          b"From: (\nSubject: hi\n\nbody\n"))
        self.assertEqual(job.status, "done")

    def test_post_without_csrf_token_is_refused(self):
        self.assert_refused(self.client.post("/analyse/ioc", data={"indicators": "10.0.0.1"}))

    def test_post_with_wrong_csrf_token_is_refused(self):
        resp = self.client.post("/analyse/ioc", data={"indicators": "10.0.0.1",
                                                      "csrf_token": "guess"})
        self.assert_refused(resp)

    def test_csrf_token_differs_between_servers(self):
        other = webapp.create_app(self.store).test_client()
        page = other.get("/").get_data(as_text=True)
        self.assertNotIn(self.csrf_token(), page)

    def test_csrf_failure_shows_error_on_the_tab_it_came_from(self):
        for tool in ("email", "ioc", "pdf"):
            with self.subTest(tool=tool):
                resp = self.client.post(f"/analyse/{tool}", data={"csrf_token": "stale"})
                self.assert_refused(resp)
                body = resp.get_data(as_text=True)
                self.assertIn(f'action="/analyse/{tool}"', body)
                self.assertIn(webapp.STALE_FORM, body)

    def test_csrf_failure_page_can_resubmit(self):
        page = self.client.post("/analyse/ioc", data={}).get_data(as_text=True)
        self.assertIn(self.csrf_token(), page)

    def test_csrf_failure_keeps_keys_out_of_page(self):
        resp = self.client.post("/analyse/ioc", data={"abuseipdb_key": SECRET})
        self.assertNotIn("KEYSECRET", resp.get_data(as_text=True))

    def test_foreign_host_is_refused(self):
        token = self.csrf_token()
        for host in ("evil.example", "evil.example:8765", "127.0.0.1.evil.example"):
            with self.subTest(host=host):
                headers = {"Host": host}
                self.assertEqual(self.client.get("/", headers=headers).status_code, 400)
                self.assert_refused(self.client.post(
                    "/analyse/ioc", data={"indicators": "10.0.0.1", "csrf_token": token},
                    headers=headers))

    def test_local_hosts_are_served(self):
        for host in ("127.0.0.1:8765", "localhost:8765", "localhost"):
            with self.subTest(host=host):
                self.assertEqual(self.client.get("/", headers={"Host": host}).status_code, 200)


if __name__ == "__main__":
    unittest.main()
