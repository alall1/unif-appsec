# python_sql_injection

## What this sample does

Uses SQLite to compare unsafe string-built SQL and safe parameterized SQL.

## Vulnerable or safe

Mixed:

- vulnerable: `vulnerable_query`
- safe comparison: `safe_query`

## Intended engine(s)

- SAST (primary)

## Expected findings

Should appear:

- SQL injection on formatted SQL string passed into `conn.execute(sql)`

Should ideally not appear:

- parameterized query pattern `conn.execute(sql, (username,))`

## Run

```bash
python samples/sast/python_sql_injection/app.py
```

## Scan

```bash
appsec scan samples/sast/python_sql_injection --sast --format json --output out/sast-sqli.json
```
