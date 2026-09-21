"""
clean_text.py - Security-Aware Text Cleaning for SIH26106 Email Threat Classification.

Design Principles:
1. Deterministic and reproducible transformations.
2. Security-aware: Preserves critical threat indicators (URLs, domains, email addresses,
   IPs, dollar amounts, phone numbers, urgency phrases, credentials, attachments).
3. Strips documented source-specific routing and mailing-list artifacts without broad regexes.
4. Preserves casing (no lowercasing), does NOT tokenize, stem, lemmatize, or remove stopwords.
"""

import html
import re
from typing import Optional


# ------------------------------------------------------------------------------
# 1. Encoding Normalization
# ------------------------------------------------------------------------------

def normalize_encoding(text: str) -> str:
    """
    Normalizes encoding artifacts commonly found in converted mbox/HTML emails.
    - Decodes standard HTML entities (&amp;, &lt;, &gt;, &quot;, &#39;, &nbsp;, etc.)
    - Normalizes non-breaking spaces, zero-width spaces, byte order marks (BOM)
    - Replaces typographic/curly quotes and dashes with standard ASCII equivalents
      to ensure uniform token boundaries during downstream modeling.
    """
    if not text:
        return ""
    
    # Decode HTML entities (safe: leaves plain text and URLs intact)
    text = html.unescape(text)
    
    # Replace non-breaking spaces and zero-width/invisible unicode characters
    text = text.replace('\xa0', ' ')
    text = text.replace('\u200b', '')   # Zero-width space
    text = text.replace('\ufeff', '')   # Byte Order Mark (BOM)
    text = text.replace('\xad', '')     # Soft hyphen
    text = text.replace('\ufffd', ' ')   # Unicode replacement character
    
    # Normalize unicode typographic quotes and dashes to standard ASCII
    # (Reason: prevents fragmentation of contractions and hyphenated threat terms)
    text = text.replace('‘', "'").replace('’', "'").replace('`', "'")
    text = text.replace('“', '"').replace('”', '"')
    text = text.replace('—', '-').replace('–', '-')
    
    return text


# ------------------------------------------------------------------------------
# 2. Whitespace & Line Ending Normalization
# ------------------------------------------------------------------------------

def normalize_whitespace(text: str) -> str:
    """
    Normalizes line endings and repeated horizontal/vertical whitespace.
    - Converts CRLF and CR to standard LF (\\n)
    - Normalizes repeated horizontal whitespace (tabs, consecutive spaces) to single space
    - Strips trailing whitespace per line
    - Collapses 3+ consecutive newlines down to a standard paragraph break (\\n\\n)
    """
    if not text:
        return ""
    
    # Normalize line endings
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    
    # Normalize horizontal whitespace per line (tabs -> spaces, collapse multiple spaces)
    # Note: does NOT collapse newlines into spaces
    lines = text.split('\n')
    cleaned_lines = []
    for line in lines:
        # Collapse horizontal whitespace
        cleaned_line = re.sub(r'[ \t\f\v]+', ' ', line).strip()
        cleaned_lines.append(cleaned_line)
    
    text = '\n'.join(cleaned_lines)
    
    # Collapse 3 or more consecutive newlines to at most 2 (standard paragraph break)
    text = re.sub(r'\n{3,}', '\n\n', text)
    
    return text.strip()


# ------------------------------------------------------------------------------
# 3. Source-Specific Artifact Stripping
# ------------------------------------------------------------------------------

def strip_source_artifacts(text: str, source: Optional[str] = None) -> str:
    """
    Removes verified, documented dataset-specific artifacts identified in the audit.
    Every rule here has an explicit documented reason.
    
    Rules:
    1. Ling-Spam: Leading 'content - length : <int>' line added during Linguist corpus creation.
    2. SpamAssassin: Yahoo! Groups / eGroups automated unsubscribe footer blocks.
    3. SpamAssassin: Residual transport header blocks dumped at the top of message body.
    4. TREC_06 / TREC_07: Standard Debian and Mailman listserv automated unsubscribe footers.
    5. CEAS_08: Synthetic testbed tracking domain '?e=<hash>@gvc.ceas-challenge.cc'.
    6. Nazario: Top-of-body mbox envelope line 'From <addr> <date>'.
    7. Nazario: Dumped top-of-body SMTP delivery headers (Delivered-To, X-Original-To).
    """
    if not text:
        return ""

    # Rule 1: Ling-Spam leading header artifact
    # Reason: The Linguist corpus prepended 'content - length : <num>' to raw bodies.
    # This is a synthetic dataset artifact, not part of the original email communication.
    if source in (None, "Ling"):
        text = re.sub(r'(?i)^\s*content\s*-\s*length\s*:\s*\d+\s*', '', text)

    # Rule 2: SpamAssassin / eGroups / Yahoo! Groups unsubscribe footer
    # Reason: Mailing list software automatically appended legal disclaimers and group
    # unsubscribe links to every post. These tokens leak source origin rather than content.
    if source in (None, "SpamAssassin"):
        # Match eGroups / Yahoo Groups unsubscribe footer block at the end of message
        text = re.sub(
            r'(?m)^[-~]{20,}.*?\nTo unsubscribe from this group[^\n]*\n[\s\S]*?(?:Your use of Yahoo! Groups is subject to [^\n]*|$)',
            '',
            text
        )
        # Rule 3: Residual transport header block at the very top of SpamAssassin body
        # Reason: A subset of SpamAssassin emails have Date/From/Message-ID dumped at start of body
        text = re.sub(
            r'^\s*Date:\s+[^\n]+\s+From:\s+[^\n]+\s+Message-ID:\s+<[^\n>]+>\s*',
            '',
            text
        )

    # Rule 4: TREC_06 / TREC_07 / Listserv automated mailing list footers
    # Reason: Legitimate messages from Debian and Mailman lists contain automated boilerplate
    # unsubscribe instructions that could cause the model to overfit on listmaster addresses.
    if source in (None, "TREC_06", "TREC_07", "SpamAssassin"):
        # Debian mailing list footer
        text = re.sub(
            r'(?m)^--\s*\nTo UNSUBSCRIBE, email to [^\n]+@lists\.debian\.org[\s\S]*?(?:Trouble\? Contact [^\n]+|$)',
            '',
            text
        )
        # Mailman general listinfo footer (e.g., R-help, Python-list)
        text = re.sub(
            r'(?m)^_{20,}\s*\n[^\n]+@(?:[a-zA-Z0-9.-]+\.)+[a-zA-Z]{2,}\s+mailing\s+list\s*\nhttps?://[^\n]+mailman/listinfo/[^\n]+[\s\S]*?(?:\n\n|\Z)',
            '',
            text
        )

    # Rule 5: CEAS-08 synthetic tracking recipient domain
    # Reason: The CEAS challenge testbed appended '?e=<hash>@gvc.ceas-challenge.cc' to URL parameters
    # to track deliveries. We strip this artificial query parameter from URLs to prevent synthetic leakage.
    if source in (None, "CEAS_08"):
        text = re.sub(
            r'\?e=[a-zA-Z0-9._%+-]+@(?:gvc\.)?ceas-challenge\.cc(?:&[a-zA-Z0-9._%+-=]+)*',
            '',
            text
        )
        text = re.sub(r'@(?:gvc\.)?ceas-challenge\.cc\b', '@recipient.invalid', text)

    # Rule 6: Nazario mbox envelope separator at the start of body
    # Reason: Raw Unix mbox 'From <address> <date>' headers were occasionally captured inside the body field.
    if source in (None, "Nazario"):
        text = re.sub(
            r'^\s*From\s+[^\s@]+@[^\s]+\s+[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s*\n',
            '',
            text
        )
        # Rule 7: Residual local delivery headers at start of Nazario body
        # E.g., 'X-Original-To: jose@login.monkey.org Delivered-To: jose@login.monkey.org'
        text = re.sub(
            r'^(?:(?:X-Original-To|Delivered-To|X-Forwarded-For|Return-Path):\s*[^\n]+\s*)+\n?',
            '',
            text
        )

    return text


# ------------------------------------------------------------------------------
# 4. Public Cleaning Interfaces
# ------------------------------------------------------------------------------

def clean_subject(subject: Optional[str], source: Optional[str] = None) -> str:
    """
    Cleans email subject line:
    - Normalizes encoding
    - Removes line breaks (subjects must be single-line)
    - Normalizes repeated spaces
    """
    if not subject or not isinstance(subject, str):
        return ""
    
    # Handle NaN or literal string 'nan'
    if subject.strip().lower() == 'nan':
        return ""
    
    text = normalize_encoding(subject)
    # Subjects should not contain internal newlines
    text = text.replace('\n', ' ').replace('\r', ' ')
    text = re.sub(r'[ \t]+', ' ', text).strip()
    return text


def clean_body(body: Optional[str], source: Optional[str] = None) -> str:
    """
    Cleans email body:
    - Normalizes encoding
    - Strips source-specific artifacts
    - Normalizes whitespace and line breaks
    """
    if not body or not isinstance(body, str):
        return ""
    
    if body.strip().lower() == 'nan':
        return ""
    
    text = normalize_encoding(body)
    text = strip_source_artifacts(text, source=source)
    text = normalize_whitespace(text)
    return text


def clean_email_text(
    subject: Optional[str],
    body: Optional[str],
    source: Optional[str] = None
) -> str:
    """
    Primary interface for creating the unified `clean_text` representation:
    subject + "\\n" + body.
    
    If subject is empty: returns clean_body.
    If body is empty: returns clean_subject.
    If both populated: returns clean_subject + "\\n" + clean_body.
    """
    c_sub = clean_subject(subject, source=source)
    c_body = clean_body(body, source=source)
    
    if c_sub and c_body:
        return f"{c_sub}\n{c_body}"
    elif c_sub:
        return c_sub
    elif c_body:
        return c_body
    else:
        return ""
