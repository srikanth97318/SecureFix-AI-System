# SecureFix AI Demonstration Guide

This walkthrough uses the SQL injection benchmark because its repair has a saved **VALIDATED** result. Re-running the repair makes a live Gemini request and consumes API quota. Use a new output directory; SecureFix does not overwrite existing reports.

The hardcoded-credential dataset is **BLOCKED** after three invalid Gemini JSON responses. It has no validated repair. Do not use it as a demo repair or treat missing test/rescan results as success.

## 1. Set up the environment

From the repository root, create and activate a virtual environment using your normal Python environment manager. Then install the project extras:

```bash
python -m pip install -e ".[dev,llm]"
python -m pip install semgrep
```

On Debian/Ubuntu, install Bubblewrap:

```bash
sudo apt-get install bubblewrap
```

Check the tools:

```bash
python --version
semgrep --version
bwrap --version
```

The recorded environment used Python 3.14.2, Semgrep 1.183.0, and Bubblewrap 0.9.0. `run` requires Semgrep, pytest dependencies in the isolated copy, and a working Bubblewrap setup.

## 2. Configure Gemini without displaying the key

Set the key in the current shell using a hidden prompt:

```bash
read -rsp "Gemini API key: " GEMINI_API_KEY
printf '\n'
export GEMINI_API_KEY
export GEMINI_MODEL=gemini-3.5-flash-lite
```

Alternatively, edit a local `.env` file and add `GEMINI_API_KEY` and `GEMINI_MODEL=gemini-3.5-flash-lite`. `.env` is ignored by Git. Never print, commit, or paste the key into reports.

Check connectivity before starting a repair:

```bash
python -m securefix.llm.connectivity
```

The command succeeds only if a small live text-generation request returns text. It reports sanitized diagnostics on failure; it must not print the key. A failed connectivity check means the repair demo is blocked—do not describe it as a successful Gemini run.

## 3. Scan the vulnerable SQL case

Use the built-in audit rules plus the SQL-specific local rule:

```bash
python -m securefix.main scan datasets/phase3/sql_injection \
  --config p/security-audit \
  --config datasets/phase3/sql_injection/securefix_sql_injection.yml \
  --output reports/demo-sql-injection-scan.json
```

The recorded original scan reported one finding and zero scanner errors: `datasets.phase3.sql_injection.securefix.python.sql-injection.string-interpolation`, severity `ERROR`, in `app.py:2`. Expected CLI summary:

```text
Scan complete: 1 finding(s); 0 scanner error(s).
Report: .../reports/demo-sql-injection-scan.json
```

The scan is read-only. It does not execute the vulnerable application or modify the fixture.

## 4. Run isolated repair and verification

Choose a new output directory before running:

```bash
python -m securefix.main run datasets/phase3/sql_injection \
  --strategy structured \
  --max-attempts 3 \
  --config p/security-audit \
  --config datasets/phase3/sql_injection/securefix_sql_injection.yml \
  --output-dir reports/demo-sql-injection-repair
```

The saved SQL workflow completed in one of at most three attempts and reported:

```text
Validation status: VALIDATED
Attempts: 1/3
Original project preserved: True
Report directory: .../reports/.../securefix-run-<run-id>
```

These are expected results based on the saved SQL workflow; a new live run can produce a different result. If Gemini returns invalid JSON, tests fail, Bubblewrap cannot start, or the rescan errors, the run is not validated.

The accepted candidate used a parameterized query:

```python
query = "SELECT * FROM users WHERE name = ?"
return cursor.execute(query, (name,)).fetchall()
```

The candidate was applied only to the disposable workspace. The recorded acceptance run passed **4 tests, 0 failed, 0 skipped**; the completed Semgrep rescan found no original or new findings and had no scanner errors. The workflow report also recorded original-source integrity as preserved.

## 5. Inspect the candidate and report

Find the run directory and inspect the generated diff:

```bash
RUN_DIR=$(find reports/demo-sql-injection-repair \
  -mindepth 1 -maxdepth 1 -type d -name 'securefix-run-*' | sort | tail -n 1)
sed -n '1,120p' "$RUN_DIR/attempt-01/candidate.diff"
```

Inspect the machine-readable result:

```bash
grep -n '"final_status"\|"passed"\|"failed"\|"skipped"\|"original_finding_remains"\|"scanner_errors"\|"preserved"' \
  "$RUN_DIR/workflow-report.json"
```

The report contains the original scan, each attempt, candidate paths, test metrics, security-rescan results, token usage when returned by Gemini, processing time, and source-integrity status. The rescan is performed by the workflow against the patched disposable copy; no standalone command can rescan that temporary copy after the run has cleaned it up.

## 6. Interpretation and limits

- `VALIDATED` means the workflow's configured patch, test, rescan, and integrity gates passed. It is not a proof of security.
- Do not run acceptance tests directly against the original vulnerable fixture and describe expected baseline failures as successful repairs. The `run` workflow executes tests against the isolated patched copy.
- Candidate code is tested with network access disabled and the original project mounted read-only. Bubblewrap is an isolation layer, not a guarantee against every sandbox or kernel escape.
- The project does not automatically apply candidate changes to the original source.
- The hardcoded-credential case remains blocked after three invalid JSON responses. No patch, candidate tests, or rescan were completed for it.
- The measured all-strategy comparison covers the four non-blocked cases only; see [the final evaluation](./reports/final-comparative-evaluation.md).
