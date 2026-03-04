#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path
from typing import Any

INVALID_FILENAME_CHARS = '<>:"/\\|?*'


def normalize_email(email: str) -> str:
    return email.strip().lower()


def decode_jwt_payload(token: str) -> dict[str, Any]:
    if not token:
        return {}

    parts = token.split(".")
    if len(parts) != 3:
        return {}

    payload_part = parts[1]
    payload_part += "=" * (-len(payload_part) % 4)

    try:
        decoded = base64.urlsafe_b64decode(payload_part.encode("ascii"))
        payload = json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}

    return payload if isinstance(payload, dict) else {}


def load_json_file(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def token_block(data: dict[str, Any]) -> dict[str, Any]:
    nested = data.get("tokens", {})
    if isinstance(nested, dict) and (
        nested.get("access_token") or nested.get("id_token") or nested.get("refresh_token")
    ):
        return nested
    return data


def extract_source_email(data: dict[str, Any], path: Path) -> str:
    tokens = token_block(data)

    email = str(tokens.get("email", "") or data.get("email", "")).strip()
    if email:
        return email

    access_payload = decode_jwt_payload(str(tokens.get("access_token", "")))
    profile = access_payload.get("https://api.openai.com/profile", {})
    if isinstance(profile, dict):
        email = str(profile.get("email", "")).strip()
        if email:
            return email

    email = str(access_payload.get("email", "")).strip()
    if email:
        return email

    if "@" in path.stem:
        return path.stem

    return ""


def extract_existing_email(data: dict[str, Any], path: Path) -> str:
    tokens = data.get("tokens", {})
    if isinstance(tokens, dict):
        email = str(tokens.get("email", "")).strip()
        if email:
            return email

    meta = data.get("meta", {})
    if isinstance(meta, dict):
        label = str(meta.get("label", "")).strip()
        if label:
            return label

    if isinstance(tokens, dict):
        access_payload = decode_jwt_payload(str(tokens.get("access_token", "")))
        profile = access_payload.get("https://api.openai.com/profile", {})
        if isinstance(profile, dict):
            email = str(profile.get("email", "")).strip()
            if email:
                return email

        email = str(access_payload.get("email", "")).strip()
        if email:
            return email

    stem = path.stem
    if "_" in stem:
        maybe_email = stem.split("_", 1)[0]
        if "@" in maybe_email:
            return maybe_email

    if "@" in stem:
        return stem

    return ""


def collect_existing_emails(tokens_dir: Path) -> set[str]:
    emails: set[str] = set()

    for path in sorted(tokens_dir.glob("*.json")):
        data = load_json_file(path)
        if not data:
            continue
        email = extract_existing_email(data, path)
        if email:
            emails.add(normalize_email(email))

    return emails


def extract_account_id(source: dict[str, Any], tokens: dict[str, Any], id_payload: dict[str, Any], access_payload: dict[str, Any]) -> str:
    raw_account_id = str(tokens.get("account_id", "") or source.get("account_id", "")).strip()
    if raw_account_id:
        return raw_account_id

    for payload in (id_payload, access_payload):
        auth_info = payload.get("https://api.openai.com/auth", {})
        if not isinstance(auth_info, dict):
            continue

        account_id = auth_info.get("chatgpt_account_id")
        if account_id:
            return str(account_id)

    return ""


def sanitize_file_fragment(value: str) -> str:
    cleaned = []
    for ch in value:
        if ch in INVALID_FILENAME_CHARS:
            cleaned.append("_")
        else:
            cleaned.append(ch)
    return "".join(cleaned)


def build_target_name(email: str, account_id: str) -> str:
    safe_email = sanitize_file_fragment(email)
    if account_id:
        safe_account_id = sanitize_file_fragment(account_id.replace("|", "_").replace("::", "__"))
        return f"{safe_email}_{safe_account_id}.json"
    return f"{safe_email}.json"


def next_available_path(path: Path) -> Path:
    if not path.exists():
        return path

    index = 1
    while True:
        candidate = path.with_name(f"{path.stem}_{index}{path.suffix}")
        if not candidate.exists():
            return candidate
        index += 1


def iso_utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def convert_record(source: dict[str, Any], email: str) -> dict[str, Any]:
    tokens = token_block(source)

    access_token = str(tokens.get("access_token", ""))
    id_token = str(tokens.get("id_token", ""))
    refresh_token = str(tokens.get("refresh_token", ""))

    access_payload = decode_jwt_payload(access_token)
    id_payload = decode_jwt_payload(id_token)

    account_id = extract_account_id(source, tokens, id_payload, access_payload)
    token_type = str(tokens.get("type", "") or source.get("type", "")).strip() or "codex"
    expired = str(tokens.get("expired", "") or source.get("expired", "")).strip()
    last_refresh = str(source.get("last_refresh", "") or tokens.get("last_refresh", "")).strip() or iso_utc_now()

    return {
        "last_refresh": last_refresh,
        "tokens": {
            "id_token": id_token,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "account_id": account_id,
            "email": email,
            "type": token_type,
            "expired": expired,
        },
    }


def convert_directory(codex_dir: Path, tokens_dir: Path, dry_run: bool, quiet: bool) -> dict[str, int]:
    existing_emails = collect_existing_emails(tokens_dir)
    source_seen: set[str] = set()

    created = 0
    skipped_existing = 0
    skipped_source_duplicates = 0
    skipped_invalid = 0

    source_paths = sorted(codex_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)

    for source_path in source_paths:
        source_data = load_json_file(source_path)
        if not source_data:
            skipped_invalid += 1
            if not quiet:
                print(f"[skip invalid] {source_path.name}")
            continue

        email = extract_source_email(source_data, source_path)
        if not email:
            skipped_invalid += 1
            if not quiet:
                print(f"[skip missing email] {source_path.name}")
            continue

        email_key = normalize_email(email)

        if email_key in existing_emails:
            skipped_existing += 1
            if not quiet:
                print(f"[skip existing] {email}")
            continue

        if email_key in source_seen:
            skipped_source_duplicates += 1
            if not quiet:
                print(f"[skip duplicate in source] {email}")
            continue

        converted = convert_record(source_data, email)
        account_id = str(converted.get("tokens", {}).get("account_id", ""))
        target_name = build_target_name(email, account_id)
        target_path = next_available_path(tokens_dir / target_name)

        if dry_run:
            print(f"[dry-run] create {target_path.name} <= {source_path.name}")
        else:
            target_path.write_text(
                json.dumps(converted, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            if not quiet:
                print(f"[created] {target_path.name}")

        created += 1
        source_seen.add(email_key)
        existing_emails.add(email_key)

    return {
        "created": created,
        "skipped_existing": skipped_existing,
        "skipped_source_duplicates": skipped_source_duplicates,
        "skipped_invalid": skipped_invalid,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Convert JSON files from codex_tokens format into tokens format, "
            "deduplicate by email, and keep source files unchanged."
        )
    )
    parser.add_argument("--codex-dir", type=Path, default=Path("codex_tokens"), help="Source folder")
    parser.add_argument("--tokens-dir", type=Path, default=Path("tokens"), help="Target folder")
    parser.add_argument("--dry-run", action="store_true", help="Preview conversion without writing files")
    parser.add_argument("--quiet", action="store_true", help="Only print summary")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    codex_dir = args.codex_dir
    tokens_dir = args.tokens_dir

    if not codex_dir.exists() or not codex_dir.is_dir():
        print(f"Error: source folder not found: {codex_dir}", file=sys.stderr)
        return 1

    if not tokens_dir.exists():
        if args.dry_run:
            print(f"[dry-run] target folder will be created: {tokens_dir}")
        else:
            tokens_dir.mkdir(parents=True, exist_ok=True)

    stats = convert_directory(codex_dir, tokens_dir, dry_run=args.dry_run, quiet=args.quiet)

    print(
        "Summary: "
        f"created={stats['created']}, "
        f"skipped_existing={stats['skipped_existing']}, "
        f"skipped_source_duplicates={stats['skipped_source_duplicates']}, "
        f"skipped_invalid={stats['skipped_invalid']}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
