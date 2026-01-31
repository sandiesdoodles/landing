#!/usr/bin/env python3
# Extract ALL "U2FsdGVk..." blobs from Phase2 HTML and decrypt with Phase2 + Phase3 keys.
# No pip deps. Needs: python3 + openssl in PATH.

import os
import re
import hashlib
import subprocess

OUTDIR = "out_gsmg_auto"
PHASE2_HTML = os.path.join(OUTDIR, "phase2.html")

PHASE2_PASS = "causality"  # Phase2 seed

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def build_phase3_chain() -> str:
    # 7 parts from community chain (case + spacing must match)
    part1 = "causality"
    part2 = "Safenet"
    part3 = "Luna"
    part4 = "HSM"
    part5 = "11110"
    part6 = "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854"
    part7 = "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"
    return part1 + part2 + part3 + part4 + part5 + part6 + part7

def run_openssl_decrypt(in_path: str, passphrase: str) -> tuple[int, str, str]:
    cmd = [
        "openssl", "enc", "-aes-256-cbc", "-d", "-a",
        "-in", in_path,
        "-pass", f"pass:{passphrase}",
    ]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

def printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    printable = 0
    for ch in s:
        o = ord(ch)
        if ch in "\n\r\t":
            printable += 1
        elif 32 <= o <= 126:
            printable += 1
    return 100.0 * printable / max(1, len(s))

def extract_all_blobs(html: str) -> list[str]:
    # Pull all OpenSSL base64 blocks beginning with U2FsdGVkX1...
    # Allow whitespace/newlines inside.
    pat = re.compile(r"(U2FsdGVkX1[0-9A-Za-z+/=\s]{40,})")
    blobs = []
    for m in pat.finditer(html):
        b = m.group(1)
        # normalize: keep only base64 charset + newlines
        b = re.sub(r"[^\n0-9A-Za-z+/=]", "", b)
        b = b.strip()
        # must start correctly
        if not b.startswith("U2FsdGVkX1"):
            continue
        # sanity length
        if len(b) < 60:
            continue
        blobs.append(b)

    # dedupe while preserving order
    seen = set()
    out = []
    for b in blobs:
        if b not in seen:
            seen.add(b)
            out.append(b)
    return out

def main():
    if not os.path.exists(PHASE2_HTML):
        print(f"[!] Missing {PHASE2_HTML}. Run your phase2 fetch script first.")
        raise SystemExit(1)

    with open(PHASE2_HTML, "r", encoding="utf-8", errors="replace") as f:
        html = f.read()

    blobs = extract_all_blobs(html)
    print(f"[*] Found {len(blobs)} OpenSSL blobs in {PHASE2_HTML}")

    if not blobs:
        print("[!] No blobs found. Something is off with the saved HTML.")
        raise SystemExit(2)

    # Keys
    k_phase2 = sha256_hex(PHASE2_PASS)
    k_phase3 = sha256_hex(build_phase3_chain())

    print(f"[+] key_phase2 = sha256('causality')      = {k_phase2}")
    print(f"[+] key_phase3 = sha256(phase3_chain)     = {k_phase3}")

    # Write & try decrypt each blob with both keys
    for i, blob in enumerate(blobs, 1):
        blob_path = os.path.join(OUTDIR, f"blob_{i:02d}.txt")
        with open(blob_path, "w", encoding="utf-8") as f:
            f.write(blob + "\n")

        for keyname, key in (("phase2key", k_phase2), ("phase3key", k_phase3)):
            rc, out, err = run_openssl_decrypt(blob_path, key)
            out_path = os.path.join(OUTDIR, f"blob_{i:02d}.{keyname}.dec.txt")

            if rc == 0 and out.strip():
                with open(out_path, "w", encoding="utf-8", errors="replace") as f:
                    f.write(out)

                pr = printable_ratio(out)
                head = out[:200].replace("\n", "\\n")
                print(f"[OK] blob_{i:02d} with {keyname}: printable={pr:.1f}%  -> {out_path}")
                print(f"     head: {head}")
            else:
                # write failure details for forensics
                fail_path = os.path.join(OUTDIR, f"blob_{i:02d}.{keyname}.fail.txt")
                with open(fail_path, "w", encoding="utf-8", errors="replace") as f:
                    f.write(err or "(no stderr)\n")
                print(f"[..] blob_{i:02d} with {keyname}: fail (saved {fail_path})")

if __name__ == "__main__":
    main()
