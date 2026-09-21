"""
email_parser.py - Standardized Email Parser for SIH26106 Forensic Pipeline.

Supports:
1. Raw RFC 822 / .eml format (bytes, string, or file).
2. Tabular row dictionaries (such as train.csv, emails_balanced.csv, raw CSVs).
3. Text bodies containing embedded RFC 822 headers.
"""

import email
from email import policy
from email.message import EmailMessage, Message
import io
import re
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field


@dataclass
class ParsedEmail:
    """Standardized representation of an email for forensic analysis."""
    email_id: str = ""
    subject: str = ""
    from_header: str = ""
    reply_to_header: str = ""
    to_headers: List[str] = field(default_factory=list)
    cc_headers: List[str] = field(default_factory=list)
    date_header: str = ""
    message_id_header: str = ""
    return_path_header: str = ""
    received_headers: List[str] = field(default_factory=list)
    auth_results_headers: List[str] = field(default_factory=list)
    dkim_signatures: List[str] = field(default_factory=list)
    spf_headers: List[str] = field(default_factory=list)
    
    body_plain: str = ""
    body_html: str = ""
    clean_text: str = ""
    
    # Attachments: list of dicts with:
    # {'filename': str, 'content_bytes': bytes, 'mime_type': str, 'size_bytes': int}
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    
    raw_headers: Dict[str, List[str]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


def _split_embedded_headers(text: str) -> (Dict[str, List[str]], str):
    """
    If raw RFC 822 headers are prepended to the body text (e.g., Nazario mbox exports),
    splits them from the message body.
    """
    headers = {}
    lines = text.splitlines()
    header_end_idx = 0
    in_headers = True

    header_re = re.compile(r"^([A-Za-z0-9\-]+):\s*(.*)$")
    continuation_re = re.compile(r"^\s+(.*)$")

    current_header = None

    for i, line in enumerate(lines):
        if not line.strip():
            # Empty line marks end of RFC 822 headers
            header_end_idx = i + 1
            break
        
        h_match = header_re.match(line)
        if h_match:
            current_header = h_match.group(1).lower()
            val = h_match.group(2)
            headers.setdefault(current_header, []).append(val)
        elif continuation_re.match(line) and current_header:
            # Multi-line folded header
            val = line.strip()
            if headers[current_header]:
                headers[current_header][-1] += " " + val
        else:
            # Non-header line before blank line -> not RFC 822 header block
            in_headers = False
            break

    # If we found known core headers (From, Received, Date, Subject, Message-ID), treat as header block
    core_headers = {"from", "received", "date", "subject", "message-id"}
    if in_headers and any(h in headers for h in core_headers):
        body_rest = "\n".join(lines[header_end_idx:])
        return headers, body_rest

    return {}, text


def parse_email_from_rfc822(raw_input: Union[str, bytes], email_id: str = "") -> ParsedEmail:
    """Parses raw RFC 822 / .eml message into ParsedEmail."""
    if isinstance(raw_input, str):
        msg = email.message_from_string(raw_input, policy=policy.default)
    else:
        msg = email.message_from_bytes(raw_input, policy=policy.default)

    pe = ParsedEmail(email_id=email_id)

    # Collect headers
    for k, v in msg.items():
        k_lower = k.lower()
        v_str = str(v)
        pe.raw_headers.setdefault(k_lower, []).append(v_str)

    pe.subject = str(msg.get("Subject", "") or "")
    pe.from_header = str(msg.get("From", "") or "")
    pe.reply_to_header = str(msg.get("Reply-To", "") or "")
    pe.date_header = str(msg.get("Date", "") or "")
    pe.message_id_header = str(msg.get("Message-ID", "") or "")
    pe.return_path_header = str(msg.get("Return-Path", "") or "")

    to_h = msg.get_all("To", [])
    pe.to_headers = [str(x) for x in to_h if x]

    cc_h = msg.get_all("Cc", [])
    pe.cc_headers = [str(x) for x in cc_h if x]

    rec_h = msg.get_all("Received", [])
    pe.received_headers = [str(x) for x in rec_h if x]

    auth_h = msg.get_all("Authentication-Results", [])
    pe.auth_results_headers = [str(x) for x in auth_h if x]

    dkim_h = msg.get_all("DKIM-Signature", [])
    pe.dkim_signatures = [str(x) for x in dkim_h if x]

    spf_h = msg.get_all("Received-SPF", [])
    pe.spf_headers = [str(x) for x in spf_h if x]

    # Walk body and attachments
    plain_parts = []
    html_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Check if attachment
            filename = part.get_filename()
            if filename or "attachment" in content_disposition.lower():
                payload = part.get_payload(decode=True) or b""
                pe.attachments.append({
                    "filename": filename or "attachment",
                    "content_bytes": payload,
                    "mime_type": content_type,
                    "size_bytes": len(payload),
                })
            else:
                if content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        plain_parts.append(payload.decode(errors="replace") if payload else "")
                    except Exception:
                        pass
                elif content_type == "text/html":
                    try:
                        payload = part.get_payload(decode=True)
                        html_parts.append(payload.decode(errors="replace") if payload else "")
                    except Exception:
                        pass
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        text_content = payload.decode(errors="replace") if payload else ""
        if content_type == "text/html":
            html_parts.append(text_content)
        else:
            plain_parts.append(text_content)

    pe.body_plain = "\n".join(plain_parts)
    pe.body_html = "\n".join(html_parts)
    pe.clean_text = pe.body_plain if pe.body_plain else pe.body_html

    return pe


def parse_email_from_dict(row: Dict[str, Any], email_id: str = "") -> ParsedEmail:
    """
    Parses a tabular record (e.g. from train.csv, emails_balanced.csv, or raw CSVs)
    into a ParsedEmail object.
    """
    rec_id = str(row.get("record_id") or row.get("id") or email_id or "rec_unknown")
    pe = ParsedEmail(email_id=rec_id)
    pe.metadata = dict(row)

    # Subject
    pe.subject = str(row.get("subject") or row.get("clean_subject") or "").strip()

    # Raw sender / from / reply_to / receiver / date / msg_id fields
    from_val = row.get("from") or row.get("sender") or row.get("From")
    if pd_not_na(from_val):
        pe.from_header = str(from_val).strip()
        pe.raw_headers["from"] = [pe.from_header]

    reply_to_val = row.get("reply_to") or row.get("Reply-To") or row.get("replyto")
    if pd_not_na(reply_to_val):
        pe.reply_to_header = str(reply_to_val).strip()
        pe.raw_headers["reply-to"] = [pe.reply_to_header]

    to_val = row.get("receiver") or row.get("to") or row.get("To")
    if pd_not_na(to_val):
        pe.to_headers = [str(to_val).strip()]
        pe.raw_headers["to"] = pe.to_headers

    cc_val = row.get("cc") or row.get("Cc")
    if pd_not_na(cc_val):
        pe.cc_headers = [str(cc_val).strip()]
        pe.raw_headers["cc"] = pe.cc_headers

    date_val = row.get("date") or row.get("Date")
    if pd_not_na(date_val):
        pe.date_header = str(date_val).strip()
        pe.raw_headers["date"] = [pe.date_header]

    msg_id_val = row.get("message_id") or row.get("Message-ID")
    if pd_not_na(msg_id_val):
        pe.message_id_header = str(msg_id_val).strip()
        pe.raw_headers["message-id"] = [pe.message_id_header]

    # Body
    raw_body = ""
    if "body" in row and pd_not_na(row["body"]):
        raw_body = str(row["body"])
    elif "clean_body" in row and pd_not_na(row["clean_body"]):
        raw_body = str(row["clean_body"])
    elif "clean_text" in row and pd_not_na(row["clean_text"]):
        raw_body = str(row["clean_text"])
    elif "text" in row and pd_not_na(row["text"]):
        raw_body = str(row["text"])

    # Check for embedded headers in the body (e.g. Nazario, SpamAssassin)
    embedded_headers, cleaned_body = _split_embedded_headers(raw_body)
    if embedded_headers:
        for k, v_list in embedded_headers.items():
            pe.raw_headers.setdefault(k, []).extend(v_list)
        if not pe.from_header and "from" in embedded_headers:
            pe.from_header = embedded_headers["from"][0]
        if not pe.reply_to_header and "reply-to" in embedded_headers:
            pe.reply_to_header = embedded_headers["reply-to"][0]
        if not pe.to_headers and "to" in embedded_headers:
            pe.to_headers = embedded_headers["to"]
        if not pe.date_header and "date" in embedded_headers:
            pe.date_header = embedded_headers["date"][0]
        if not pe.message_id_header and "message-id" in embedded_headers:
            pe.message_id_header = embedded_headers["message-id"][0]
        if "received" in embedded_headers:
            pe.received_headers.extend(embedded_headers["received"])
        if "received-spf" in embedded_headers:
            pe.spf_headers.extend(embedded_headers["received-spf"])
        if "dkim-signature" in embedded_headers:
            pe.dkim_signatures.extend(embedded_headers["dkim-signature"])
        if "authentication-results" in embedded_headers:
            pe.auth_results_headers.extend(embedded_headers["authentication-results"])

    # Detect HTML presence
    if "<html" in cleaned_body.lower() or "<body" in cleaned_body.lower() or "<div" in cleaned_body.lower():
        pe.body_html = cleaned_body
        pe.body_plain = re.sub(r"<[^>]+>", " ", cleaned_body)
    else:
        pe.body_plain = cleaned_body

    pe.clean_text = str(row.get("clean_text") or cleaned_body).strip()

    # Pass attachments if present in row
    if "attachments" in row and isinstance(row["attachments"], list):
        pe.attachments = row["attachments"]

    return pe


def pd_not_na(val: Any) -> bool:
    """Helper to check not-null safely without importing pandas inside loop."""
    if val is None:
        return False
    val_str = str(val).strip().lower()
    return val_str not in ("", "nan", "none", "null")


def parse_email(input_data: Any, email_id: str = "") -> ParsedEmail:
    """Universal email parser entrypoint."""
    if isinstance(input_data, ParsedEmail):
        return input_data
    if isinstance(input_data, dict):
        return parse_email_from_dict(input_data, email_id=email_id)
    if isinstance(input_data, bytes):
        return parse_email_from_rfc822(input_data, email_id=email_id)
    if isinstance(input_data, str):
        # Check if it looks like raw RFC 822 or just plain text
        if re.search(r"^(From:|Received:|Return-Path:|Message-ID:|Date:)", input_data, re.MULTILINE | re.IGNORECASE):
            return parse_email_from_rfc822(input_data, email_id=email_id)
        else:
            return parse_email_from_dict({"clean_text": input_data}, email_id=email_id)
    return ParsedEmail(email_id=email_id)
