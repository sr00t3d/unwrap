# unwrap — Static PHP Malware & Obfuscation Deobfuscator (`v2.0.0`)

A modern, standalone Bash + Python 3 CLI for **statically unwrapping multi-layer obfuscated PHP malware and webshells** (`eval`, `gzinflate`, `base64_decode`, `str_rot13`, `gzuncompress`, `gzdecode`, `hex2bin`, `strrev`, `urldecode`) — replacing legacy 2011 Python 2 `unwrap` with safe byte-level decoding, webshell indicator detection, and `table` / `json` / `csv` outputs.

## Historical Modernization

Inspired by the original **`unwrap`** Python 2 script (**© 2011 — HostGator.com, LLC**), created to statically decode obfuscated PHP webshells without executing untrusted code.

In `v2.0.0`, the tool was completely rewritten in **Bash + Python 3.6+ (stdlib)**:
- **Removed Dead Python 2 APIs**: Replaced `from string import letters`, `.encode('rot13')`, `.decode('base64')`, and `optparse` with Python 3 `codecs`, `base64`, `zlib`, and `argparse`.
- **Byte-Safe Recursive Unwrapping**: Fixed the 2011 `shlex.shlex` / `;` splitting bug that broke on raw compressed binary bytes inside `gzinflate(...)`.
- **Expanded Transforms & Forensics**: Added `gzdecode`, `strrev`, `hex2bin`, `urldecode`, `\xHH` escape decoding, recursive directory scanning (`-r`), and automatic webshell indicator flagging (`system`, `shell_exec`, `passthru`, `$_POST`).

## Real Output Example

```text
$ ./unwrap.sh /tmp/unwrap-e2e/shell.php --no-color
=== unwrap.sh v2.0.0 | Static PHP Deobfuscator ===
  File:       /tmp/unwrap-e2e/shell.php
  Layers:     4 (str_rot13 -> base64_decode -> gzinflate -> eval)
  Indicators: $_POST, system
  Decoded:
    system($_POST['cmd']);
----------------------------------------------------------------------------
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
