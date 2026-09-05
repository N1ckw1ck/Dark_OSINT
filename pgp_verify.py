#!/usr/bin/env python3

'''
Dark web PGP signature verifier

Verifies a signed message against a site's published PGP public key.
Useful for checking canary statements, site authenticity, or any
signed message a dark web operator publishes.

Usage:
    python pgp_verify.py [--debug]

Dependencies:
    python-gnupg (see requirements.txt)
    gpg must be installed on the system (gpg or gpg2)
'''

from __future__ import annotations

import os
import sys
import tempfile
import textwrap
from datetime import datetime, timezone
from typing import Any, Literal

import gnupg # type: ignore[import-untyped] no stub types

# Constants
BANNER = r'''

▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
██ ▄█▀ ▄█▀     PGP Verifier    ▀█▄ ▀█▄ ██
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

PGP Authenticity Checker
'''

DIVIDER: str = "─" * 60

PGP_END_MARKERS: tuple[str, ...] = (
    "-----END PGP PUBLIC KEY BLOCK-----",
    "-----END PGP SIGNED MESSAGE-----",
    "-----END PGP SIGNATURE-----",
)

SignatureMode = Literal["clearsigned", "detached"]


# Helpers 
def print_divider() -> None:
    print(DIVIDER)

def collect_pgp_block(prompt: str) -> str:
    print(prompt)
    print("  (Input stops automatically after the closing marker)\n")

    lines: list[str] = []
    seen_end_marker = False

    while True:
        try:
            line = input()
        except EOFError:
            break

        lines.append(line)

        if any(marker in line for marker in PGP_END_MARKERS):
            seen_end_marker = True
            continue

        if seen_end_marker and line.strip() == "":
            break

    return "\n".join(lines).strip()


def collect_plain_text(prompt: str) -> str:
    print(prompt)
    print("  (Press Enter twice on a blank line when done)\n")

    lines: list[str] = []
    consecutive_blanks = 0

    while True:
        try:
            line = input()
        except EOFError:
            break

        if line.strip() == "":
            consecutive_blanks += 1
            if consecutive_blanks >= 2:
                break
        else:
            consecutive_blanks = 0

        lines.append(line)

    return "\n".join(lines).strip()

def detect_mode(text: str) -> SignatureMode | None:
    '''Return the signature mode implied by *text*, or None if unrecognised.'''
    if "-----BEGIN PGP SIGNED MESSAGE-----" in text:
        return "clearsigned"
    if "-----BEGIN PGP SIGNATURE-----" in text:
        return "detached"
    return None

def format_fingerprint(fp: str) -> str:
    '''Format a 40-char fingerprint into space-separated 4-char groups.'''
    clean = fp.upper().replace(" ", "")
    return " ".join(clean[i : i + 4] for i in range(0, len(clean), 4))

def format_timestamp(raw: str | int | None) -> str:
    '''Convert a Unix timestamp (string or int) to a human-readable UTC string.'''
    if raw is None:
        return "unknown"
    try:
        dt = datetime.fromtimestamp(int(raw), tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError, OverflowError):
        return str(raw)

def attr(obj: Any, name: str, default: str = "") -> str:
    '''Safely retrieve a string attribute from an untyped gnupg result object.'''
    value = getattr(obj, name, None)
    return str(value) if value is not None else default


# Collect inputs
def collect_pubkey() -> str:
    print("\n[1/3] PUBLIC KEY")
    pubkey = collect_pgp_block("Paste the site's PGP public key block:")

    if "-----BEGIN PGP PUBLIC KEY BLOCK-----" not in pubkey:
        sys.exit(
            "\n[ERROR] Input does not look like a valid PGP public key block.\n"
            "        Expected to find: -----BEGIN PGP PUBLIC KEY BLOCK-----"
        )

    return pubkey


def collect_signed_content() -> tuple[SignatureMode, str, str | None]:
    '''Return (mode, primary_text, optional_plain_message).

    For clearsigned mode the primary text IS the full signed block.
    For detached mode the primary text is the signature block and
    plain message is returned separately.
    '''
    print_divider()
    print("\n[2/3] SIGNED MESSAGE / SIGNATURE")
    print("What do you have?")
    print("  [1] A clearsigned message (message AND signature together)")
    print("  [2] A detached signature (separate from the message)\n")

    while True:
        choice = input("Enter 1 or 2: ").strip()
        if choice in ("1", "2"):
            break
        print("Please enter 1 or 2.")

    if choice == "1":
        signed_block = collect_pgp_block("\nPaste the full clearsigned message block:")
        if detect_mode(signed_block) != "clearsigned":
            sys.exit(
                "\n[ERROR] This doesn't appear to be a clearsigned PGP block.\n"
                "        Expected: -----BEGIN PGP SIGNED MESSAGE-----"
            )
        return "clearsigned", signed_block, None

    plain = collect_plain_text("\nPaste the plain message text (without any PGP headers):")
    sig_block = collect_pgp_block("\nPaste the detached PGP signature block:")

    if "-----BEGIN PGP SIGNATURE-----" not in sig_block:
        sys.exit(
            "\n[ERROR] This doesn't appear to be a valid PGP signature block.\n"
            "        Expected: -----BEGIN PGP SIGNATURE-----"
        )

    return "detached", sig_block, plain

# Verification
def verify(
    pubkey: str,
    mode: SignatureMode,
    primary: str,
    plain_message: str | None,
    *,
    debug: bool,
) -> int:
    '''Import *pubkey*, run GPG verification, print results. Returns exit code.'''
    print_divider()
    print("\n[3/3] VERIFYING...\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        os.chmod(tmpdir, 0o700)

        gpg: Any = gnupg.GPG(gnupghome=tmpdir)
        gpg.encoding = "utf-8"

        import_result: Any = gpg.import_keys(pubkey)

        if not import_result.count:
            sys.exit(
                "[ERROR] Failed to import the public key.\n"
                "        Check that the key block is complete and unmodified."
            )

        fingerprints: list[str] = import_result.fingerprints or []
        imported_fp: str = fingerprints[0] if fingerprints else "unknown"

        result: Any
        if mode == "clearsigned":
            asc_path = os.path.join(tmpdir, "message.asc")
            with open(asc_path, "w", encoding="utf-8") as fh:
                fh.write(primary)
            with open(asc_path, "rb") as fh:
                result = gpg.verify_file(fh)
        else:
            sig_path = os.path.join(tmpdir, "message.sig")
            msg_path = os.path.join(tmpdir, "message.txt")
            with open(sig_path, "w", encoding="utf-8") as fh:
                fh.write(primary)
            with open(msg_path, "w", encoding="utf-8") as fh:
                fh.write(plain_message or "")
            with open(sig_path, "rb") as fh:
                result = gpg.verify_file(fh, msg_path)

        valid: bool = bool(result)

        # Print results
        print_divider()
        print()
        print(
            "  ✓  SIGNATURE VALID — message is authentic"
            if valid
            else "  ✗  SIGNATURE INVALID — possible compromise or tampering"
        )
        print()
        print_divider()
        print()

        sig_fp: str = attr(result, "fingerprint")
        sig_keyid: str = attr(result, "key_id")
        timestamp: str = attr(result, "timestamp") or attr(result, "sig_timestamp")
        username: str = attr(result, "username")

        print(f"  Imported key fingerprint : {format_fingerprint(imported_fp)}")

        if sig_fp:
            print(f"  Signing key fingerprint  : {format_fingerprint(sig_fp)}")
            if sig_fp.upper() != imported_fp.upper():
                print()
                print("  [!] WARNING: The signing key does NOT match the imported public key.")
                print("      The message was signed by a different key than the one you provided.")
                print("      This is a strong indicator of compromise or key substitution.")
        elif sig_keyid:
            print(f"  Signing key ID           : {sig_keyid}")

        if username:
            print(f"  Key identity (UID)       : {username}")

        if timestamp:
            print(f"  Signature timestamp      : {format_timestamp(timestamp)}")

        if not valid:
            status: str = attr(result, "status")
            stderr: str = attr(result, "stderr")
            if status:
                print(f"\n  GPG status               : {status}")
            if debug and stderr:
                print(f"\n  GPG stderr:\n{textwrap.indent(stderr, '    ')}")
            print()
            print("  Possible reasons for failure:")
            print("   • The message was altered after signing")
            print("   • The signature belongs to a different key (key substitution attack)")
            print("   • The public key provided is not the real site key")
            print("   • The signature block was truncated or corrupted")
            print()
            print("  RECOMMENDATION: Do not trust this site or message.")
        else:
            print()
            print("  The message was signed with the private key corresponding to")
            print("  the public key you provided. The content has not been altered.")

        print()
        print_divider()
        print()

        return 0 if valid else 1

# Entry point
def main() -> int:
    debug = "--debug" in sys.argv

    print(BANNER)
    print("This tool verifies that a message was signed by a site's known PGP key.")
    print("If verification fails, the site may be compromised, spoofed, or the")
    print("message may have been tampered with.\n")
    print_divider()

    pubkey = collect_pubkey()
    mode, primary, plain_message = collect_signed_content()

    return verify(pubkey, mode, primary, plain_message, debug=debug)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n[Aborted]")
        sys.exit(130)