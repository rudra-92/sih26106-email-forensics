"""Example execution demonstrating Module 1 on a synthetic spoofed email."""

import json
from modules.sender_identity import analyze_eml

SYNTHETIC_SPOOFED_EML = (
    b"From: \"Microsoft Support Team\" <billing-alert@fake-ms-portal.com>\r\n"
    b"To: <cfo@victim-enterprise.com>\r\n"
    b"Reply-To: <credential-drop@external-harvest.net>\r\n"
    b"Return-Path: <bounce@unregistered-relay.org>\r\n"
    b"Message-ID: <server99.sys@rogue-host.info>\r\n"
    b"Subject: Action Required: Your 365 Subscription Suspended\r\n"
    b"Authentication-Results: mx.victim-enterprise.com; "
    b"spf=fail smtp.mailfrom=fake-ms-portal.com; "
    b"dkim=fail header.d=fake-ms-portal.com; "
    b"dmarc=fail (p=REJECT) header.from=fake-ms-portal.com\r\n"
    b"Received: from rogue-host.info ([198.51.100.77]) "
    b"by relay.victim-enterprise.com ([203.0.113.15]) with ESMTP; "
    b"Sun, 20 Sep 2026 02:30:00 +0000\r\n"
    b"\r\n"
    b"Dear Customer, your subscription has failed. Please re-authenticate."
)

if __name__ == "__main__":
    report = analyze_eml(SYNTHETIC_SPOOFED_EML, email_id="E001")
    print(json.dumps(report.to_dict(), indent=2))
