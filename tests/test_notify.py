"""Composing and sending notifications, without a network."""

import hashlib
import hmac
import json

import pytest

from fleetwright import notify


def _item(subject, body="", link=None, urgent=False, event="run_failed"):
    return {"event": event, "subject": subject, "body": body, "link": link, "urgent": urgent, "created_at": None}


def test_one_event_is_sent_as_itself():
    m = notify.compose([_item("Run #4 Nightly: failed", "2 failed", "https://fw/runs/4", True)])
    assert m["subject"] == "Run #4 Nightly: failed"
    assert m["text"] == "2 failed\n\nhttps://fw/runs/4"
    assert m["urgent"] and m["link"] == "https://fw/runs/4"


def test_several_events_become_one_digest():
    m = notify.compose([_item("web1 is unreachable", "agent not connected", "https://fw/hosts/1", True),
                        _item("Run #5 Patch: done", "5 done", event="run_done")])
    assert m["subject"] == "FleetWright: 2 things need attention"
    assert "• web1 is unreachable" in m["text"] and "• Run #5 Patch: done" in m["text"]
    assert m["urgent"]
    assert [e["event"] for e in m["events"]] == ["run_failed", "run_done"]


def test_webhook_body_is_slack_compatible_and_signed():
    m = notify.compose([_item("Run #4 Nightly: failed", "2 failed")])
    body = notify.webhook_payload(m)
    data = json.loads(body)
    assert data["text"].startswith("*Run #4 Nightly: failed*")
    assert data["source"] == "fleetwright" and data["events"][0]["subject"] == "Run #4 Nightly: failed"
    sig = notify.signature("s3cret", body)
    assert sig == "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()


class _Sent:
    def __init__(self):
        self.requests = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)

        class R:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                return b""
        return R()


def test_ntfy_sends_title_priority_and_click(monkeypatch):
    sent = _Sent()
    monkeypatch.setattr(notify.urllib.request, "urlopen", sent)
    monkeypatch.setattr(notify.security, "decrypt", lambda v: "tk_123")
    channel = {"kind": "ntfy", "config": {"url": "https://ntfy.example/fleet"}, "secret_enc": "x", "name": "n"}
    notify.send(channel, notify.compose([_item("web1 is unreachable", "gone", "https://fw/hosts/1", True)]))
    req = sent.requests[0]
    assert req.full_url == "https://ntfy.example/fleet"
    assert req.get_header("Title") == "web1 is unreachable"
    assert req.get_header("Priority") == "high" and req.get_header("Click") == "https://fw/hosts/1"
    assert req.get_header("Authorization") == "Bearer tk_123"
    assert req.data.startswith(b"gone")


def test_webhook_signs_when_it_has_a_secret(monkeypatch):
    sent = _Sent()
    monkeypatch.setattr(notify.urllib.request, "urlopen", sent)
    monkeypatch.setattr(notify.security, "decrypt", lambda v: "s3cret")
    channel = {"kind": "webhook", "config": {"url": "https://hooks.example/x"}, "secret_enc": "x", "name": "w"}
    notify.send(channel, notify.compose([_item("hello")]))
    req = sent.requests[0]
    assert req.get_header("X-fleetwright-signature") == notify.signature("s3cret", req.data)


def test_bad_urls_and_incomplete_email_are_refused():
    with pytest.raises(notify.SendError, match="https://"):
        notify.send({"kind": "webhook", "config": {"url": "file:///etc/passwd"}, "secret_enc": None},
                    notify.compose([_item("x")]))
    with pytest.raises(notify.SendError, match="SMTP server"):
        notify.send({"kind": "email", "config": {"host": "smtp.example"}, "secret_enc": None},
                    notify.compose([_item("x")]))
