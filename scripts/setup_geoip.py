#!/usr/bin/env python
"""Local GeoIP & threat infrastructure dataset setup script for Module 5.

Downloads and validates free offline datasets required by the forensic platform:
1. DB-IP Lite IP-to-City (MMDB format)
2. DB-IP Lite IP-to-ASN (MMDB format)
3. Tor Project bulk exit list (optional contextual feed)

Licensing & Attribution:
- DB-IP Lite is licensed under Creative Commons Attribution 4.0 International (CC BY 4.0).
  "IP geolocation and ASN data provided by DB-IP Lite, licensed under CC BY 4.0."
- The Tor bulk exit list is a free public feed provided by The Tor Project.

Offline Safety:
- No paid APIs, no API keys, and no live network calls during email analysis.
- Database downloads are performed solely during offline setup/maintenance.
"""

import argparse
from datetime import datetime, timezone
import gzip
import ipaddress
from pathlib import Path
import sys
import urllib.error
import urllib.request

# Safe Windows stdout encoding
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = PROJECT_ROOT / "data" / "geoip"

TOR_BULK_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"


def get_candidate_releases() -> list[str]:
    """Generate candidate year-month release strings (current month, then previous months)."""
    now = datetime.now(timezone.utc)
    candidates = []
    # Current month and previous 3 months
    y = now.year
    m = now.month
    for _ in range(4):
        candidates.append(f"{y:04d}-{m:02d}")
        m -= 1
        if m == 0:
            m = 12
            y -= 1
    # Ensure known working fallback release is included
    if "2026-09" not in candidates:
        candidates.append("2026-09")
    return candidates


def validate_mmdb(file_path: Path, expected_type_substr: str = "") -> bool:
    """Validate that a file is a non-empty, readable MMDB database."""
    if not file_path.is_file() or file_path.stat().st_size < 1024 * 50:
        return False
    try:
        import maxminddb

        with maxminddb.open_database(str(file_path)) as reader:
            meta = reader.metadata()
            db_type = getattr(meta, "database_type", "")
            if expected_type_substr and expected_type_substr.lower() not in db_type.lower():
                return False
            # Test query
            reader.get("8.8.8.8")
        return True
    except Exception:
        return False


def validate_tor_feed(file_path: Path) -> bool:
    """Validate that a file is a non-empty text feed containing valid IP addresses."""
    if not file_path.is_file() or file_path.stat().st_size < 100:
        return False
    try:
        valid_ips = 0
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    try:
                        ipaddress.ip_address(s)
                        valid_ips += 1
                    except ValueError:
                        pass
        return valid_ips >= 50
    except Exception:
        return False


def download_stream(url: str, dest_path: Path) -> bool:
    """Download a URL to a local destination file with progress reporting."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; SIH26106-Setup/1.0)"},
    )
    tmp_path = dest_path.with_suffix(dest_path.suffix + ".download")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            total_size = int(resp.headers.get("content-length", 0))
            downloaded = 0
            with open(tmp_path, "wb") as out_f:
                while True:
                    chunk = resp.read(1024 * 1024)  # 1MB chunks
                    if not chunk:
                        break
                    out_f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        pct = (downloaded / total_size) * 100.0
                        sys.stdout.write(
                            f"\r  Progress: {downloaded / (1024 * 1024):.1f} MB / "
                            f"{total_size / (1024 * 1024):.1f} MB ({pct:.1f}%)"
                        )
                    else:
                        sys.stdout.write(f"\r  Progress: {downloaded / (1024 * 1024):.1f} MB")
                    sys.stdout.flush()
        print()
        if dest_path.is_file():
            dest_path.unlink()
        tmp_path.replace(dest_path)
        return True
    except urllib.error.HTTPError as e:
        print(f"\n  HTTP Error {e.code}: {e.reason}")
        if tmp_path.is_file():
            tmp_path.unlink()
        return False
    except Exception as e:
        print(f"\n  Download failed: {e}")
        if tmp_path.is_file():
            tmp_path.unlink()
        return False


def decompress_gz_stream(gz_path: Path, target_path: Path) -> bool:
    """Safely stream-decompress a .gz file into the target file."""
    tmp_target = target_path.with_suffix(target_path.suffix + ".extracting")
    try:
        with gzip.open(gz_path, "rb") as in_gz, open(tmp_target, "wb") as out_f:
            while True:
                chunk = in_gz.read(1024 * 1024 * 4)  # 4MB buffer
                if not chunk:
                    break
                out_f.write(chunk)
        if target_path.is_file():
            target_path.unlink()
        tmp_target.replace(target_path)
        return True
    except Exception as e:
        print(f"  Decompression error: {e}")
        if tmp_target.is_file():
            tmp_target.unlink()
        return False


def setup_dbip_dataset(
    dataset_name: str,
    target_filename: str,
    expected_substr: str,
    data_dir: Path,
    preferred_release: str | None = None,
    force: bool = False,
) -> bool:
    """Download, decompress, and validate a DB-IP Lite dataset."""
    target_path = data_dir / target_filename

    # 1. Check if already present and valid
    if target_path.is_file() and not force:
        if validate_mmdb(target_path, expected_substr):
            size_mb = target_path.stat().st_size / (1024 * 1024)
            print(f"[FOUND] {target_filename} already exists and is valid ({size_mb:.1f} MB). Skipping.")
            return True
        print(f"[WARN] {target_filename} exists but failed validation. Re-downloading...")

    print(f"\n[DOWNLOADING] {dataset_name} ({target_filename})...")
    candidates = [preferred_release] if preferred_release else get_candidate_releases()
    dest_gz = data_dir / f"{target_filename}.gz"

    downloaded = False
    for release in candidates:
        if not release:
            continue
        url = f"https://download.db-ip.com/free/{dataset_name}-{release}.mmdb.gz"
        print(f"  Trying release '{release}': {url}")
        if download_stream(url, dest_gz):
            downloaded = True
            break

    if not downloaded:
        print(f"[ERROR] Could not download {dataset_name} from DB-IP Lite.")
        return False

    # 2. Decompress safely
    print(f"  Decompressing {dest_gz.name} -> {target_filename}...")
    if not decompress_gz_stream(dest_gz, target_path):
        print(f"[ERROR] Failed to decompress {dest_gz.name}")
        return False

    # 3. Clean up .gz archive
    if dest_gz.is_file():
        dest_gz.unlink()

    # 4. Validate output MMDB
    if not validate_mmdb(target_path, expected_substr):
        print(f"[ERROR] Decompressed file {target_filename} failed MMDB validation.")
        if target_path.is_file():
            target_path.unlink()
        return False

    size_mb = target_path.stat().st_size / (1024 * 1024)
    print(f"[SUCCESS] {target_filename} verified and ready ({size_mb:.1f} MB).")
    return True


def setup_tor_feed(data_dir: Path, force: bool = False) -> bool:
    """Download and validate the Tor Project bulk exit list."""
    target_path = data_dir / "tor_exit_nodes.txt"

    if target_path.is_file() and not force:
        if validate_tor_feed(target_path):
            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [l for l in f if l.strip() and not l.startswith("#")]
            print(f"[FOUND] tor_exit_nodes.txt already exists and is valid ({len(lines)} IPs). Skipping.")
            return True
        print("[WARN] tor_exit_nodes.txt exists but failed validation. Re-downloading...")

    print(f"\n[DOWNLOADING] Tor Bulk Exit List from {TOR_BULK_EXIT_LIST_URL}...")
    if not download_stream(TOR_BULK_EXIT_LIST_URL, target_path):
        print("[WARN] Could not download Tor bulk exit list. Forensic engine will operate without Tor indicators.")
        return False

    if not validate_tor_feed(target_path):
        print("[WARN] Downloaded Tor exit list failed validation.")
        if target_path.is_file():
            target_path.unlink()
        return False

    with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [l for l in f if l.strip() and not l.startswith("#")]
    print(f"[SUCCESS] tor_exit_nodes.txt verified ({len(lines)} active Tor exit IPs).")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download and verify free offline DB-IP Lite datasets and Tor exit list for Module 5."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help="Target data directory (default: data/geoip/)",
    )
    parser.add_argument(
        "--release",
        type=str,
        default=None,
        help="Specific DB-IP release year-month (e.g. 2026-09)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-download even if valid database files exist",
    )
    parser.add_argument(
        "--skip-tor",
        action="store_true",
        help="Skip downloading the optional Tor Project bulk exit list",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check and validate existing database files without downloading",
    )

    args = parser.parse_args()
    data_dir: Path = args.data_dir.resolve()
    data_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 68)
    print("SIH26106: MODULE 5 LOCAL ENRICHMENT ENVIRONMENT SETUP")
    print("=" * 68)
    print(f"Data Directory : {data_dir}")
    print("Primary Source : DB-IP Lite (Free MMDB format, CC BY 4.0)")
    print("Optional Feed  : The Tor Project Bulk Exit List")
    print("-" * 68)

    if args.check:
        print("\nChecking local dataset status:")
        city_ok = validate_mmdb(data_dir / "dbip-city-lite.mmdb", "city")
        asn_ok = validate_mmdb(data_dir / "dbip-asn-lite.mmdb", "asn")
        tor_ok = validate_tor_feed(data_dir / "tor_exit_nodes.txt")
        print(f"  City MMDB     : {'VALID' if city_ok else 'MISSING / INVALID'}")
        print(f"  ASN MMDB      : {'VALID' if asn_ok else 'MISSING / INVALID'}")
        print(f"  Tor Exit Feed : {'VALID' if tor_ok else 'MISSING / INVALID'}")
        return 0 if (city_ok and asn_ok) else 1

    # 1. Setup City MMDB
    city_ok = setup_dbip_dataset(
        dataset_name="dbip-city-lite",
        target_filename="dbip-city-lite.mmdb",
        expected_substr="city",
        data_dir=data_dir,
        preferred_release=args.release,
        force=args.force,
    )

    # 2. Setup ASN MMDB
    asn_ok = setup_dbip_dataset(
        dataset_name="dbip-asn-lite",
        target_filename="dbip-asn-lite.mmdb",
        expected_substr="asn",
        data_dir=data_dir,
        preferred_release=args.release,
        force=args.force,
    )

    # 3. Setup Tor Exit Feed
    tor_ok = True
    if not args.skip_tor:
        tor_ok = setup_tor_feed(data_dir=data_dir, force=args.force)

    print("\n" + "=" * 68)
    print("SETUP STATUS SUMMARY:")
    print(f"  DB-IP City Lite : {'READY' if city_ok else 'FAILED'}")
    print(f"  DB-IP ASN Lite  : {'READY' if asn_ok else 'FAILED'}")
    print(f"  Tor Exit List   : {'READY' if tor_ok else 'NOT INSTALLED (OPTIONAL)'}")
    print("=" * 68)

    if city_ok and asn_ok:
        print("\nAll required datasets are verified. Module 5 local enrichment is fully operational.")
        return 0
    else:
        print("\n[ERROR] Setup incomplete. Please review network connectivity or download manually.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
