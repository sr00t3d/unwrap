#!/usr/bin/env bash
# ==============================================================================
# unwrap.sh — Static PHP Malware & Obfuscation Deobfuscator CLI (v2.0.0)
# Modernized clean-room implementation inspired by legacy unwrap (2011).
# Copyright (c) 2026 Percio Castelo — Apache-2.0 License
# ==============================================================================
set -euo pipefail

VERSION="2.0.0"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required (3.6+)." >&2
    exit 1
fi

read -r -d '' PY_SCRIPT << 'EOF' || true
import argparse
import base64
import codecs
import csv
import io
import json
import os
import re
import sys
import urllib.parse
import zlib

VERSION = "2.0.0"

PHP_BLOCK_RX = re.compile(r"<\?(?:php|=)?(.*?)(?:\?>|\Z)", re.DOTALL | re.IGNORECASE)
CALL_RX = re.compile(
    r"""^\s*(eval|assert|stripslashes|base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|urldecode|rawurldecode)\s*\(\s*(.*)\s*\)\s*;?\s*$""",
    re.DOTALL | re.IGNORECASE,
)
INDICATORS_RX = re.compile(
    r"\b(shell_exec|system|passthru|exec|proc_open|popen|pcntl_exec|curl_exec|file_put_contents|move_uploaded_file|create_function)\b|\$_(?:POST|GET|REQUEST|COOKIE)\b",
    re.IGNORECASE,
)
HEX_ESC_RX = re.compile(rb"\\x([0-9a-fA-F]{2})")


class Colors:
    def __init__(self, enabled=True):
        self.RESET = "\033[0m" if enabled else ""
        self.BOLD = "\033[1m" if enabled else ""
        self.CYAN = "\033[36m" if enabled else ""
        self.GREEN = "\033[32m" if enabled else ""
        self.YELLOW = "\033[33m" if enabled else ""
        self.RED = "\033[31m" if enabled else ""
        self.DIM = "\033[2m" if enabled else ""


def unquote_php_string(raw_bytes):
    s = raw_bytes.strip()
    if len(s) >= 2 and s[0:1] == b"'" and s[-1:] == b"'":
        inner = s[1:-1].replace(b"\\'", b"'").replace(b"\\\\", b"\\")
        return inner, True
    if len(s) >= 2 and s[0:1] == b'"' and s[-1:] == b'"':
        inner = s[1:-1]
        inner = HEX_ESC_RX.sub(lambda m: bytes([int(m.group(1), 16)]), inner)
        inner = inner.replace(b'\\"', b'"').replace(b"\\\\", b"\\")
        return inner, True
    return raw_bytes, False


def apply_transform(func_name, payload_bytes):
    fn = func_name.lower()
    if fn in ("eval", "assert", "stripslashes"):
        inner, _ = unquote_php_string(payload_bytes)
        return inner
    if fn == "base64_decode":
        inner, _ = unquote_php_string(payload_bytes)
        cleaned = re.sub(rb"\s+", b"", inner)
        return base64.b64decode(cleaned)
    if fn == "gzinflate":
        inner, _ = unquote_php_string(payload_bytes)
        return zlib.decompress(inner, -zlib.MAX_WBITS)
    if fn == "gzuncompress":
        inner, _ = unquote_php_string(payload_bytes)
        return zlib.decompress(inner)
    if fn == "gzdecode":
        inner, _ = unquote_php_string(payload_bytes)
        return zlib.decompress(inner, 16 + zlib.MAX_WBITS)
    if fn == "str_rot13":
        inner, _ = unquote_php_string(payload_bytes)
        return codecs.decode(inner.decode("latin-1"), "rot_13").encode("latin-1")
    if fn == "strrev":
        inner, _ = unquote_php_string(payload_bytes)
        return inner[::-1]
    if fn == "hex2bin":
        inner, _ = unquote_php_string(payload_bytes)
        return bytes.fromhex(inner.decode("ascii").strip())
    if fn in ("urldecode", "rawurldecode"):
        inner, _ = unquote_php_string(payload_bytes)
        return urllib.parse.unquote_to_bytes(inner.decode("latin-1"))
    raise ValueError(f"Unsupported transform: {func_name}")


def unwrap_expression(expr_bytes, max_depth=25):
    chain = []
    current = expr_bytes.strip()
    for _ in range(max_depth):
        text = current.decode("latin-1").strip()
        if text.startswith("<?php"):
            text = text[5:].strip()
        elif text.startswith("<?"):
            text = text[2:].strip()
        if text.endswith("?>"):
            text = text[:-2].strip()

        m = CALL_RX.match(text)
        if not m:
            break
        fn = m.group(1).lower()
        arg_str = m.group(2).strip()
        # Recursively unwrap inner call first if it's itself a function call
        inner_bytes = arg_str.encode("latin-1")
        if CALL_RX.match(arg_str):
            inner_decoded, sub_chain = unwrap_expression(inner_bytes, max_depth=max_depth - len(chain) - 1)
            chain.extend(sub_chain)
            inner_bytes = inner_decoded
        try:
            next_bytes = apply_transform(fn, inner_bytes)
        except Exception:
            break
        chain.append(fn)
        if next_bytes == current:
            break
        current = next_bytes
    return current, chain


def analyze_file(path, raw_bytes, max_depth):
    text = raw_bytes.decode("latin-1", errors="replace")
    blocks = PHP_BLOCK_RX.findall(text)
    if not blocks:
        blocks = [text]

    best_chain = []
    decoded_parts = []
    for blk in blocks:
        blk_strip = blk.strip()
        if not blk_strip:
            continue
        dec_bytes, chain = unwrap_expression(blk_strip.encode("latin-1"), max_depth=max_depth)
        if chain:
            best_chain.extend(chain)
            decoded_parts.append(dec_bytes.decode("utf-8", errors="replace"))

    decoded_text = "\n".join(decoded_parts)
    indicators = sorted(set(m.group(0) for m in INDICATORS_RX.finditer(decoded_text or text)))
    return {
        "file": path,
        "layers": len(best_chain),
        "chain": " -> ".join(best_chain) if best_chain else "-",
        "indicators": indicators,
        "decoded": decoded_text,
    }


def collect_targets(paths, recursive):
    files = []
    for p in paths:
        if p == "-":
            files.append("-")
            continue
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p) and recursive:
            for root, dirs, fnames in os.walk(p, followlinks=False):
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
                for fn in fnames:
                    if fn.lower().endswith((".php", ".phtml", ".inc", ".php5", ".php7")):
                        files.append(os.path.join(root, fn))
    return sorted(set(files))


def render_table(results, show_code, c):
    print(f"{c.BOLD}{c.CYAN}=== unwrap.sh v{VERSION} | Static PHP Deobfuscator ==={c.RESET}")
    if not results:
        print("  No files analyzed.")
        return
    for r in results:
        st_col = c.RED if r["layers"] > 0 else c.GREEN
        ind_str = ", ".join(r["indicators"]) if r["indicators"] else "none"
        print(f"  {c.BOLD}File:{c.RESET}       {r['file']}")
        print(f"  {c.BOLD}Layers:{c.RESET}     {st_col}{r['layers']}{c.RESET} ({r['chain']})")
        print(f"  {c.BOLD}Indicators:{c.RESET} {c.YELLOW if r['indicators'] else c.DIM}{ind_str}{c.RESET}")
        if r["decoded"] and show_code:
            print(f"  {c.BOLD}Decoded:{c.RESET}")
            for line in r["decoded"].splitlines()[:30]:
                print(f"    {line}")
        print("-" * 76)


def render_csv(results):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["file", "layers", "chain", "indicators", "decoded_preview"])
    for r in results:
        prev = r["decoded"].replace("\n", " ")[:120]
        w.writerow([r["file"], r["layers"], r["chain"], ";".join(r["indicators"]), prev])
    sys.stdout.write(buf.getvalue())


def main():
    parser = argparse.ArgumentParser(
        prog="unwrap.sh",
        description="Static PHP Malware & Obfuscation Deobfuscator CLI (v2.0.0)",
    )
    parser.add_argument("targets", nargs="*", default=["-"], help="PHP files, directories (with -r), or '-' for stdin")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan directories for PHP files")
    parser.add_argument("--max-depth", type=int, default=25, help="Max nested obfuscation layers (default: 25)")
    parser.add_argument("--no-code", action="store_true", help="Hide decoded payload preview in table output")
    parser.add_argument("--only-obfuscated", action="store_true", help="Only show files with >= 1 unwrapped layer")
    parser.add_argument("-o", "--output", choices=["table", "json", "csv"], default="table", help="Output format")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("-v", "--version", action="version", version=f"unwrap.sh {VERSION}")
    args = parser.parse_args()

    files = collect_targets(args.targets, args.recursive)
    results = []
    for f in files:
        if f == "-":
            raw = sys.stdin.buffer.read()
        else:
            with open(f, "rb") as fh:
                raw = fh.read()
        res = analyze_file(f, raw, args.max_depth)
        if args.only_obfuscated and res["layers"] == 0:
            continue
        results.append(res)

    if args.output == "json":
        print(json.dumps(results, indent=2))
    elif args.output == "csv":
        render_csv(results)
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        render_table(results, not args.no_code, Colors(enabled=use_color))


if __name__ == "__main__":
    main()
EOF

python3 -c "$PY_SCRIPT" "$@"
