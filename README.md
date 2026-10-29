# Clipboard (clip2)

A small end-to-end encrypted clipboard: paste text on one device, copy it on another.
It is one static web page plus a Python command-line client, with Supabase as storage.

- **Zero-knowledge server.** Usernames, passphrases and clip text never leave your device.
  The server stores only AES-256-GCM ciphertext, tagged with a hash of a token derived from them.
- **No accounts, no signup.** Any username + passphrase combination is its own clipboard, empty at first.
- **Clips expire.** Each clip expires after 5 minutes to 7 days (7 days by default) and can be deleted earlier.
- **No dependencies.** The page uses no external scripts, and the CLI needs only the Python 3.8+ standard library.

## Files

| File | What it is |
|---|---|
| `index.html` | The web client: one self-contained page, with links to `clip.py` and this README. |
| `clip.py` | Stateless command-line client that reads and writes the same clips as the page. Hosted next to `index.html`. |
| `clip2_schema.sql` | Database setup for Supabase: one table, RPC functions and the cleanup job. |

## How it works

```
username + passphrase
        │  PBKDF2-SHA256, 600 000 iterations, salt = "clipboard/v2/" + username
        ▼
     master key ──HKDF "enc"──▶ AES-256-GCM key  (stays on the device)
                └─HKDF "auth"─▶ token            (sent to the server)

server:  clip2_clips.owner   = sha256(token)
         clip2_clips.content = "v2.<iv>.<ciphertext>"   (base64)
```

- **No accounts.** There is only one table, `clip2_clips`. Each clip carries `owner = sha256(token)`,
  and every function filters by it. The username works as a salt and as a second secret,
  so two people choosing the same username with different passphrases get two separate clipboards.
  Nothing on the server records usernames, signups or clipboards that hold no clips.
- **No typo detection.** A wrong username or passphrase isn't an error: it opens a different, empty clipboard.
  The page and CLI say so when the list is empty, so check for typos if you expected clips.
- **Padding.** Before encryption the text is stored as a 4-byte length, the UTF-8 text, then zero bytes,
  rounded up to a multiple of 512 bytes. The server only learns a size range.
- **Access control.** The browser and CLI call PostgREST RPC functions with the public (publishable) key.
  Row-level security is on and API roles have no direct table access,
  so the functions are the only way in, and each checks the token.
- **Cleanup.** A `pg_cron` job deletes expired clips every 10 minutes.
  Once a clipboard's last clip is gone, nothing about it remains on the server.

### What the server can still see

- How many clips there are, and which clips belong to the same clipboard (they share an `owner` hash).
- Each clip's size, rounded to 512 bytes.
- When clips are created and when they expire.
- The IP addresses of requests.

It cannot see clip text or usernames.

### What you are trusting

- **Your passphrase.** Losing the username or the passphrase means losing the clips. There is no recovery.
- **Passphrase strength.** Anyone who steals the database can try to guess username + passphrase offline,
  so use the page's **Generate** button (about 125 bits) or another strong passphrase.
- **The page you load.** Whoever controls where `index.html` is served from could change it to steal keys.
  Host it somewhere you control, or open a local copy you have checked.

## Setup

### 1. Database (Supabase)

1. Turn on the **pg_cron** extension (Database → Extensions).
   The script also tries `create extension pg_cron` itself.
2. Open the SQL Editor, paste `clip2_schema.sql` and run it.

The script can be run again safely, but **each run drops all `clip2_*` tables and their data.**

### 2. Web page

1. Check `SUPABASE_URL` and `SUPABASE_KEY` near the top of the `<script>` in `index.html`.
   Use the project's publishable key, never the secret key.
2. If you change the URL, also change `connect-src` in the `Content-Security-Policy` meta tag,
   or the page will be blocked from reaching the server.
3. Host `index.html`, `clip.py` and `README.md` together in the same folder, over **HTTPS** (GitHub Pages, Netlify, Cloudflare Pages, Supabase Storage, …).
   Browsers only allow WebCrypto and the clipboard API in a secure context,
   so plain `http://` works only on `localhost`.

### 3. CLI

After logging in, click **Download CLI**. This is an ordinary link to `clip.py` in the same folder as the page,
so the file must be uploaded alongside `index.html`.
It reads `CLIP_URL` and `CLIP_KEY` from the environment if you need to point it at another project.

## Usage

### Web

1. Enter a username and passphrase and press **Unlock**.
   A new combination simply opens a new, empty clipboard. If you expected clips and see none,
   press **Log out** and check both for typos.
2. **Generate** creates a strong random passphrase inside the browser and copies it to the clipboard.
   Save it in a password manager.
3. **Remember on this device** keeps you logged in. The encryption key is stored in the browser's IndexedDB
   in a form scripts can use but not read out. **Log out** (top right, next to your username) removes it and returns to the login screen, where you can switch to another username + passphrase.
4. Choose the expiry before pressing **Save**. Ctrl/⌘+Enter also saves.
   The list refreshes when you come back to the tab.
5. **Delete all clips** empties the clipboard. You're asked to type your username to confirm.

### CLI

```
python3 clip.py <user> <secret> <command> [<arguments>]
```

Words in `<angle brackets>` are values you fill in; everything else is typed as shown.
`<secret>` can be `-` (a dash), which asks for the passphrase instead of taking it on the command line.
Passing the passphrase directly works for scripts, but it shows up in shell history and process lists.

```sh
python3 clip.py bob - list                       # id, time, expiry, first line
python3 clip.py bob - last | pbcopy              # newest clip (Linux: xclip -sel c, Windows: clip)
python3 clip.py bob - get 42
python3 clip.py bob - add "some text" -t 1h      # expiry: 5m / 1h / 1d / 7d (default 7d)
echo "some text" | python3 clip.py bob - add     # no text given: reads stdin
python3 clip.py bob - rm 42 43
python3 clip.py bob - clear                      # delete all clips (asks first; -y skips)
```

Run `python3 clip.py -h`, or just `python3 clip.py`, for the full help.

## Operations

### Updating the CLI

Replace `clip.py` on the host. The page links to it directly, so the page itself doesn't change.

### Checking the cleanup job

```sql
select jobid, jobname, schedule, active from cron.job;
select status, return_message, start_time
  from cron.job_run_details order by start_time desc limit 10;

-- pause / resume
select cron.unschedule('clip2-purge-expired');
-- (re-run the cron.schedule(...) statement at the end of clip2_schema.sql to restore it)
```

### Usage numbers

```sql
select count(distinct owner) as clipboards,
       count(*) as live_clips,
       pg_size_pretty(sum(length(content))::bigint) as ciphertext
  from clip2_clips where expires_at > now();
select pg_size_pretty(pg_total_relation_size('clip2_clips')) as table_size;
```

### Deleting data

```sql
delete from clip2_clips;      -- everything
```

You can't delete one particular person's clips from the server side, because nothing links an `owner` hash to a username.
Users delete their own clips with **Delete all clips** or `clear`.

### Limits

| Limit | Value | Where to change it |
|---|---|---|
| Clip size | 200 000 characters of ciphertext (about 145 KB of text) | DB `check` constraint, `MAX_CT` in `index.html` and `clip.py` |
| Clips per clipboard | 500 live | `clip2_add` |
| Clips returned by list | 200 newest | `clip2_list` |
| Expiry | 1 minute to 7 days | `clip2_add`, the `clip2_clips_ttl` constraint, the page's expiry options |

There is no rate limiting. Anyone can write to a new clipboard, so the per-clipboard clip cap is the main protection against abuse.
Supabase's own API limits still apply.

### Changes that make existing clips unreadable

Changing the PBKDF2 iteration count, the salt prefix `clipboard/v2/`, the HKDF labels or the token format
gives every user a different key, so their old clips can no longer be decrypted.
If you ever need to, bump the version (`clipboard/v3/`, `"v3."` blobs) and let old clips expire.
Change the page and the CLI together. Their crypto has to stay byte-identical.

## Troubleshooting

| Symptom | Cause |
|---|---|
| "No clips for this username + passphrase" when you expected some | A typo in the username or passphrase, or the clips have expired. The username is case-insensitive and surrounding spaces are ignored. |
| `[cannot decrypt]` on a clip | The clip was written with a different key or format. This shouldn't happen within one clipboard. |
| Page stuck or `crypto.subtle` undefined | The page isn't served over HTTPS. |
| "Failed to fetch" or a CSP error in the console | `connect-src` in the CSP doesn't match `SUPABASE_URL`. |
| **Download CLI** gives a 404 | `clip.py` isn't uploaded next to `index.html`. |
| HTTP 401 or 404 from the RPCs | Wrong API key, or `clip2_schema.sql` hasn't been run. |
| Paste button blocked | The browser denied clipboard read access. Paste into the box instead. |
