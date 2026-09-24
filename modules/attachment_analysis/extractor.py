"""Attachment extractor for MIME email messages.

Extracts attachment payloads and metadata directly from parsed email.message.Message
or EmailMessage objects, raw MIME bytes, or structured message inputs.

Processes all attachments strictly in-memory without saving arbitrary files to disk.
"""

from email import message_from_bytes, message_from_string, policy
from email.header import decode_header, make_header
from email.message import EmailMessage, Message
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .models import ExtractedAttachment


def _decode_mime_header(header_val: Optional[str]) -> str:
    """Safely decode RFC 2047 encoded MIME header strings."""
    if not header_val:
        return ""
    try:
        decoded = decode_header(header_val)
        return str(make_header(decoded))
    except Exception:
        return str(header_val)


class AttachmentExtractor:
    """Extracts attachment artifacts and metadata from email MIME structures."""

    def __init__(self) -> None:
        pass

    def extract(
        self,
        email_input: Union[EmailMessage, Message, bytes, str, Path, Dict[str, Any], List[Any]],
    ) -> List[ExtractedAttachment]:
        """Extract all attachments from the provided email input.

        Args:
            email_input: EmailMessage, Message, raw MIME bytes/str, Path to .eml,
                         or a list/dict of pre-extracted attachment descriptors.

        Returns:
            List of ExtractedAttachment objects with complete in-memory provenance.
        """
        # 1. Handle pre-extracted attachment list/objects directly
        if isinstance(email_input, list):
            results: List[ExtractedAttachment] = []
            for idx, item in enumerate(email_input, start=1):
                att = self._normalize_attachment_item(item, idx)
                if att:
                    results.append(att)
            return results

        if isinstance(email_input, dict) and "attachments" in email_input:
            return self.extract(email_input["attachments"])

        # 2. Parse MIME structure to email.message.Message if raw bytes/str/Path
        msg: Optional[Message] = None
        if isinstance(email_input, (EmailMessage, Message)):
            msg = email_input
        elif isinstance(email_input, bytes):
            msg = message_from_bytes(email_input, policy=policy.default)
        elif isinstance(email_input, str):
            # Check if input is a file path
            is_file = False
            if "\n" not in email_input and "\r" not in email_input and len(email_input) < 1024:
                try:
                    p = Path(email_input)
                    if p.is_file():
                        raw_bytes = p.read_bytes()
                        msg = message_from_bytes(raw_bytes, policy=policy.default)
                        is_file = True
                except (OSError, ValueError):
                    is_file = False

            if not is_file:
                msg = message_from_string(email_input, policy=policy.default)
        elif isinstance(email_input, Path):
            raw_bytes = email_input.read_bytes()
            msg = message_from_bytes(raw_bytes, policy=policy.default)

        if msg is None:
            return []

        return self._extract_from_mime_message(msg)

    def _extract_from_mime_message(self, msg: Message) -> List[ExtractedAttachment]:
        """Traverse MIME parts and capture attachment payloads."""
        attachments: List[ExtractedAttachment] = []
        att_counter = 1

        # Walk all parts of the MIME message
        for part in msg.walk():
            # Skip container parts
            if part.is_multipart():
                continue

            # Determine content-disposition
            disposition: Optional[str] = None
            raw_disposition = part.get("Content-Disposition")
            if raw_disposition:
                try:
                    disposition = part.get_content_disposition()
                except Exception:
                    disposition = "attachment" if "attachment" in raw_disposition.lower() else (
                        "inline" if "inline" in raw_disposition.lower() else None
                    )

            # Get filename
            filename: Optional[str] = None
            try:
                filename = part.get_filename()
            except Exception:
                pass

            if not filename:
                # Fallback to name parameter in Content-Type
                name_param = part.get_param("name")
                if name_param:
                    if isinstance(name_param, tuple):
                        name_str = name_param[2] if len(name_param) > 2 else str(name_param)
                    else:
                        name_str = str(name_param)
                    filename = _decode_mime_header(name_str)

            if filename:
                filename = _decode_mime_header(filename).strip()

            content_id = part.get("Content-ID")
            if content_id:
                content_id = content_id.strip("<> \t\r\n")

            content_type = part.get_content_type() or "application/octet-stream"

            # Determine whether this part is an attachment:
            # - Explicit Content-Disposition: attachment
            # - Explicit Content-Disposition: inline with filename or content-id
            # - Has a filename parameter
            # - Non-text type (e.g. application/*, image/*) that is not the main message body
            is_attachment_part = False
            is_inline = False

            if disposition == "attachment":
                is_attachment_part = True
            elif disposition == "inline":
                if filename or content_id:
                    is_attachment_part = True
                    is_inline = True
            elif filename:
                is_attachment_part = True
            elif content_type.lower() not in ("text/plain", "text/html"):
                # Binary payload without explicit disposition
                is_attachment_part = True

            if not is_attachment_part:
                continue

            # Extract raw payload bytes
            raw_bytes = self._extract_part_bytes(part)
            if raw_bytes is None:
                continue

            att_id = f"ATT-{att_counter:03d}"
            att_counter += 1

            effective_filename = filename if filename else f"attachment_{att_id}"
            sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

            attachments.append(
                ExtractedAttachment(
                    attachment_id=att_id,
                    filename=effective_filename,
                    declared_mime=content_type.lower(),
                    content_disposition=disposition,
                    content_id=content_id,
                    size=len(raw_bytes),
                    raw_bytes=raw_bytes,
                    sha256=sha256_hash,
                    is_inline=is_inline,
                )
            )

        return attachments

    def _extract_part_bytes(self, part: Message) -> Optional[bytes]:
        """Safely extract decoded raw bytes from a MIME part."""
        try:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                return payload
            if isinstance(payload, str):
                return payload.encode("utf-8")
        except Exception:
            pass

        try:
            raw = part.get_payload()
            if isinstance(raw, bytes):
                return raw
            if isinstance(raw, str):
                return raw.encode("utf-8")
        except Exception:
            pass

        return None

    def _normalize_attachment_item(self, item: Any, index: int) -> Optional[ExtractedAttachment]:
        """Convert an existing attachment item or dict into ExtractedAttachment."""
        if isinstance(item, ExtractedAttachment):
            return item

        if isinstance(item, dict):
            raw_bytes = item.get("raw_bytes", b"")
            if isinstance(raw_bytes, str):
                raw_bytes = raw_bytes.encode("latin-1")
            size = item.get("size", len(raw_bytes))
            sha256_hash = item.get("sha256") or hashlib.sha256(raw_bytes).hexdigest()
            att_id = item.get("attachment_id", f"ATT-{index:03d}")
            filename = item.get("filename", f"attachment_{att_id}")
            declared_mime = item.get("declared_mime", "application/octet-stream")
            content_disposition = item.get("content_disposition")
            content_id = item.get("content_id")
            is_inline = item.get("is_inline", content_disposition == "inline")

            return ExtractedAttachment(
                attachment_id=att_id,
                filename=filename,
                declared_mime=declared_mime.lower(),
                content_disposition=content_disposition,
                content_id=content_id,
                size=size,
                raw_bytes=raw_bytes,
                sha256=sha256_hash,
                is_inline=is_inline,
            )

        return None


def extract_attachments(
    email_input: Union[EmailMessage, Message, bytes, str, Path, Dict[str, Any], List[Any]],
) -> List[ExtractedAttachment]:
    """Convenience helper to extract attachments from email content."""
    return AttachmentExtractor().extract(email_input)
