#!/usr/bin/env python3
"""
Encrypted clipboard, command-line client. Compatible with index.html.
Run `python3 clip.py -h` for usage.

No dependencies: Python 3.8+ standard library only.
(If the `cryptography` package is installed it is used automatically for speed.)
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone


# ---------- AES-256-GCM: pure Python, standard library only ----------
# Used unless the `cryptography` package happens to be installed (then that is
# used instead, as it is much faster). Verified against NIST GCM test vectors.
def _aes_tables():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF        # p *= 3
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF               # q /= 3
        if q & 0x80:
            q ^= 0x09
        rot = lambda v, s: ((v << s) | (v >> (8 - s))) & 0xFF
        sbox[p] = q ^ rot(q, 1) ^ rot(q, 2) ^ rot(q, 3) ^ rot(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    xt = lambda a: ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1
    t0 = [(xt(s) << 24) | (s << 16) | (s << 8) | (xt(s) ^ s) for s in sbox]
    ror = lambda v, n: ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF
    return sbox, t0, [ror(v, 8) for v in t0], [ror(v, 16) for v in t0], [ror(v, 24) for v in t0]


_SBOX, _T0, _T1, _T2, _T3 = _aes_tables()


class _PyAESGCM:
    """Same interface as cryptography's AESGCM (96-bit IV, 128-bit tag)."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 key required")
        s = _SBOX
        w = list(struct.unpack(">8I", key))
        rcon = 1
        for i in range(8, 60):
            t = w[i - 1]
            if i % 8 == 0:
                t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF
                t = (s[t >> 24] << 24 | s[(t >> 16) & 255] << 16 | s[(t >> 8) & 255] << 8 | s[t & 255]) ^ (rcon << 24)
                rcon = ((rcon << 1) ^ 0x1B) & 0xFF if rcon & 0x80 else rcon << 1
            elif i % 8 == 4:
                t = s[t >> 24] << 24 | s[(t >> 16) & 255] << 16 | s[(t >> 8) & 255] << 8 | s[t & 255]
            w.append(w[i - 8] ^ t)
        self._rk = w
        self._h = int.from_bytes(self._block(0), "big")

    def _block(self, n: int) -> bytes:
        rk, T0, T1, T2, T3, S = self._rk, _T0, _T1, _T2, _T3, _SBOX
        s0 = (n >> 96) ^ rk[0]
        s1 = ((n >> 64) & 0xFFFFFFFF) ^ rk[1]
        s2 = ((n >> 32) & 0xFFFFFFFF) ^ rk[2]
        s3 = (n & 0xFFFFFFFF) ^ rk[3]
        for r in range(4, 56, 4):
            s0, s1, s2, s3 = (
                T0[s0 >> 24] ^ T1[(s1 >> 16) & 255] ^ T2[(s2 >> 8) & 255] ^ T3[s3 & 255] ^ rk[r],
                T0[s1 >> 24] ^ T1[(s2 >> 16) & 255] ^ T2[(s3 >> 8) & 255] ^ T3[s0 & 255] ^ rk[r + 1],
                T0[s2 >> 24] ^ T1[(s3 >> 16) & 255] ^ T2[(s0 >> 8) & 255] ^ T3[s1 & 255] ^ rk[r + 2],
                T0[s3 >> 24] ^ T1[(s0 >> 16) & 255] ^ T2[(s1 >> 8) & 255] ^ T3[s2 & 255] ^ rk[r + 3],
            )
        f = lambda a, b, c, d, k: (S[a >> 24] << 24 | S[(b >> 16) & 255] << 16 | S[(c >> 8) & 255] << 8 | S[d & 255]) ^ k
        return struct.pack(">4I", f(s0, s1, s2, s3, rk[56]), f(s1, s2, s3, s0, rk[57]),
                           f(s2, s3, s0, s1, rk[58]), f(s3, s0, s1, s2, rk[59]))

    def _gmul(self, x: int) -> int:
        z, v = 0, self._h
        for i in range(127, -1, -1):
            if (x >> i) & 1:
                z ^= v
            v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
        return z

    def _tag(self, j0: int, aad: bytes, ct: bytes) -> bytes:
        y = 0
        for data in (aad, ct):
            for i in range(0, len(data), 16):
                y = self._gmul(y ^ int.from_bytes(data[i:i + 16].ljust(16, b"\0"), "big"))
        y = self._gmul(y ^ ((len(aad) * 8) << 64 | len(ct) * 8))
        return (y ^ int.from_bytes(self._block(j0), "big")).to_bytes(16, "big")

    def _ctr(self, j0: int, data: bytes) -> bytes:
        out = bytearray(len(data))
        ctr = j0
        for i in range(0, len(data), 16):
            ctr = (ctr & ~0xFFFFFFFF) | ((ctr + 1) & 0xFFFFFFFF)
            ks = self._block(ctr)
            chunk = data[i:i + 16]
            out[i:i + len(chunk)] = (int.from_bytes(chunk, "big") ^ int.from_bytes(ks[:len(chunk)], "big")).to_bytes(len(chunk), "big")
        return bytes(out)

    def encrypt(self, iv: bytes, data: bytes, aad) -> bytes:
        j0 = int.from_bytes(iv + b"\0\0\0\1", "big")
        ct = self._ctr(j0, data)
        return ct + self._tag(j0, aad or b"", ct)

    def decrypt(self, iv: bytes, data: bytes, aad) -> bytes:
        if len(iv) != 12 or len(data) < 16:
            raise ValueError("bad input")
        j0 = int.from_bytes(iv + b"\0\0\0\1", "big")
        ct, tag = data[:-16], data[-16:]
        if not hmac.compare_digest(self._tag(j0, aad or b"", ct), tag):
            raise ValueError("authentication failed")
        return self._ctr(j0, ct)


try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM   # optional speed-up
except ImportError:
    AESGCM = _PyAESGCM

SUPABASE_URL = os.environ.get("CLIP_URL", "https://wtdfjfvjpczaffzjicpj.supabase.co")
SUPABASE_KEY = os.environ.get("CLIP_KEY", "sb_publishable_KZDb1BR4p6RRcUpzeQTdrg_-lQYdCgC")
KDF_ITER = 600_000
PAD = 512
MAX_CT = 200_000


class ApiError(Exception):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


# ---------- crypto (must match index.html) ----------
def _hkdf(prk_key: bytes, info: bytes, length: int = 32) -> bytes:
    # RFC 5869 with empty salt (= HashLen zero bytes), as WebCrypto does.
    prk = hmac.new(b"\0" * 32, prk_key, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def derive(user: str, secret: str):
    user = user.strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,32}", user):
        sys.exit("username: 3-32 characters, a-z 0-9 _ . -")
    master = hashlib.pbkdf2_hmac("sha256", secret.encode(), ("clipboard/v2/" + user).encode(), KDF_ITER, 32)
    aes_key = _hkdf(master, b"enc")
    token = base64.b64encode(_hkdf(master, b"auth")).decode()
    return aes_key, token


def encrypt(aes_key: bytes, text: str) -> str:
    data = text.encode()
    size = -(-(len(data) + 4) // PAD) * PAD
    buf = struct.pack(">I", len(data)) + data
    buf += b"\0" * (size - len(buf))
    iv = secrets.token_bytes(12)
    ct = AESGCM(aes_key).encrypt(iv, buf, None)
    return "v2." + base64.b64encode(iv).decode() + "." + base64.b64encode(ct).decode()


def decrypt(aes_key: bytes, blob: str):
    try:
        v, iv, ct = blob.split(".")
        if v != "v2":
            return None
        buf = AESGCM(aes_key).decrypt(base64.b64decode(iv), base64.b64decode(ct), None)
        (n,) = struct.unpack(">I", buf[:4])
        if n > len(buf) - 4:
            return None
        return buf[4:4 + n].decode()
    except Exception:
        return None


# ---------- API ----------
def rpc(fn: str, args: dict):
    req = urllib.request.Request(
        f"{SUPABASE_URL}/rest/v1/rpc/{fn}",
        data=json.dumps(args).encode(),
        headers={"apikey": SUPABASE_KEY, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()
            return json.loads(body) if body else None
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            j = json.loads(raw)
            raise ApiError(j.get("message") or f"HTTP {e.code}", j.get("code")) from None
        except (ValueError, AttributeError):
            raise ApiError(f"HTTP {e.code}: {raw[:200]!r}") from None
    except urllib.error.URLError as e:
        raise ApiError(f"network error: {e.reason}") from None


# ---------- helpers ----------
def parse_ttl(s: str) -> int:
    m = re.fullmatch(r"(\d+)\s*([smhd]?)", s.strip().lower())
    if not m:
        raise argparse.ArgumentTypeError("use e.g. 300, 5m, 1h, 1d, 7d")
    n = int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    if not 60 <= n <= 604800:
        raise argparse.ArgumentTypeError("ttl must be between 1m and 7d")
    return n


def ts(s: str) -> datetime:
    # Postgres trims fractional seconds ("…:05.12+00:00"); Python < 3.11 needs 0 or 6 digits.
    s = re.sub(r"\.(\d+)", lambda m: "." + (m.group(1) + "000000")[:6], s.replace("Z", "+00:00"))
    return datetime.fromisoformat(s)


def fmt_left(exp: datetime) -> str:
    m = int((exp - datetime.now(timezone.utc)).total_seconds() // 60)
    if m < 1:
        return "<1m"
    if m < 60:
        return f"{m}m"
    if m < 48 * 60:
        return f"{m // 60}h"
    return f"{m // 1440}d"


def fetch(aes_key, token):
    rows = rpc("clip2_list", {"p_token": token})
    for r in rows:
        r["text"] = decrypt(aes_key, r["content"])
    return rows


# ---------- commands ----------
def cmd_list(a, key, tok):
    rows = fetch(key, tok)
    if not rows:
        print("(no clips for this username + passphrase)", file=sys.stderr)
    for r in rows:
        created = ts(r["created_at"]).astimezone().strftime("%Y-%m-%d %H:%M")
        text = "[cannot decrypt]" if r["text"] is None else r["text"]
        first = text.strip().splitlines()[0] if text.strip() else ""
        if len(first) > a.width:
            first = first[: a.width - 1] + "…"
        extra = "" if "\n" not in text.strip() else f"  (+{text.strip().count(chr(10))} lines)"
        print(f"{r['id']:>6}  {created}  exp {fmt_left(ts(r['expires_at'])):>4}  {first}{extra}")


def _print_raw(text):
    sys.stdout.write(text)
    if sys.stdout.isatty() and not text.endswith("\n"):
        sys.stdout.write("\n")


def cmd_last(a, key, tok):
    rows = fetch(key, tok)
    if not rows:
        sys.exit("no clips")
    if rows[0]["text"] is None:
        sys.exit("cannot decrypt newest clip")
    _print_raw(rows[0]["text"])


def cmd_get(a, key, tok):
    for r in fetch(key, tok):
        if r["id"] == a.id:
            if r["text"] is None:
                sys.exit("cannot decrypt")
            return _print_raw(r["text"])
    sys.exit(f"clip {a.id} not found")


def cmd_add(a, key, tok):
    text = a.text if a.text not in (None, "-") else sys.stdin.read()
    if not text.strip():
        sys.exit("nothing to add")
    blob = encrypt(key, text)
    if len(blob) > MAX_CT:
        sys.exit("too large (max ~145 KB of text)")
    nid = rpc("clip2_add", {"p_token": tok, "p_content": blob, "p_ttl_seconds": a.ttl})
    print(nid, file=sys.stderr)


def cmd_rm(a, key, tok):
    for i in a.ids:
        rpc("clip2_delete", {"p_token": tok, "p_id": i})


def cmd_clear(a, key, tok):
    if not a.yes:
        if input("Delete ALL clips in this clipboard? type 'yes': ") != "yes":
            sys.exit("aborted")
    n = rpc("clip2_delete_all", {"p_token": tok})
    print(f"deleted {n} clip(s)", file=sys.stderr)


COMMANDS = ("list", "ls", "last", "get", "add", "rm", "clear")

USAGE = "usage: python3 clip.py <user> <secret> <command> [<arguments>]\n"

HELP = """\
clip.py - encrypted clipboard, command-line client

Usage:
  python3 clip.py <user> <secret> <command> [<arguments>]

  Words in <angle brackets> are values you fill in.
  All other words are typed exactly as shown.

  <user>      your username, e.g. bob
  <secret>    your passphrase, or - (a dash) to be asked for it
              (the dash keeps it out of shell history)
  <command>   one of the commands below

  Each <user> + <secret> pair is its own clipboard. A new pair starts empty,
  so if you see no clips, check both for typos.

Commands:
  list                show your clips: id, time, expiry, first line
  last                print the newest clip
  get <id>            print clip number <id>
  add <text>          store <text>
  add                 store whatever comes in on stdin
      -t <time>       for add: expire after <time>: 5m, 1h, 1d, 7d (default 7d)
  rm <id> [<id>...]   delete clips by number
  clear               delete all clips (asks first; add -y to skip asking)

Examples, for user bob:
  python3 clip.py bob - list
  python3 clip.py bob - last | pbcopy        (Linux: xclip -sel c, Windows: clip)
  python3 clip.py bob - get 42
  python3 clip.py bob - add "some text" -t 1h
  echo "some text" | python3 clip.py bob - add
  python3 clip.py bob - rm 42 43
  python3 clip.py bob - clear
"""


class _Parser(argparse.ArgumentParser):
    """argparse with hand-written help: the generated sections were confusing."""

    def format_usage(self):
        return USAGE

    def format_help(self):
        return HELP

    def error(self, message):
        sys.stderr.write(f"{USAGE}error: {message}\nRun 'python3 clip.py -h' for help.\n")
        sys.exit(2)


def main():
    p = _Parser(prog="clip.py")
    p.add_argument("user", metavar="<user>")
    p.add_argument("secret", metavar="<secret>")
    sub = p.add_subparsers(dest="cmd", metavar="<command>", parser_class=_Parser, required=True)

    s = sub.add_parser("list", aliases=["ls"])
    s.add_argument("-w", "--width", type=int, default=80)
    s.set_defaults(fn=cmd_list)
    sub.add_parser("last").set_defaults(fn=cmd_last)
    s = sub.add_parser("get")
    s.add_argument("id", metavar="<id>", type=int)
    s.set_defaults(fn=cmd_get)
    s = sub.add_parser("add")
    s.add_argument("text", metavar="<text>", nargs="?")
    s.add_argument("-t", "--ttl", metavar="<time>", type=parse_ttl, default=604800)
    s.set_defaults(fn=cmd_add)
    s = sub.add_parser("rm")
    s.add_argument("ids", metavar="<id>", type=int, nargs="+")
    s.set_defaults(fn=cmd_rm)
    s = sub.add_parser("clear")
    s.add_argument("-y", "--yes", action="store_true")
    s.set_defaults(fn=cmd_clear)

    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(HELP)
        sys.exit(0)
    # Common mistakes: command first, or <secret> left out.
    if argv[0] in COMMANDS:
        p.error(f"<user> and <secret> come before the command: python3 clip.py <user> <secret> {argv[0]}")
    if len(argv) >= 2 and argv[1] in COMMANDS:
        p.error(f"<secret> is missing: python3 clip.py {argv[0]} <secret> {argv[1]}   (use - to be asked)")

    a = p.parse_args(argv)
    secret = getpass.getpass("Passphrase: ") if a.secret == "-" else a.secret
    if not secret:
        sys.exit("empty passphrase")
    key, tok = derive(a.user, secret)
    try:
        a.fn(a, key, tok)
    except ApiError as e:
        sys.exit(f"error: {e}")
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
