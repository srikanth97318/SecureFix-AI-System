# SecureFix AI — Final Comparative Evaluation

- **Evaluation date:** 2026-11-02
- **Gemini model:** `gemini-3.5-flash-lite`
- **Semgrep:** 1.183.0
- **Controlled evaluation report:** [evaluation-report.json](./phase3-comparison-20261102/evaluation-report.json)
- **Framework summary:** [evaluation-summary.txt](./phase3-comparison-20261102/evaluation-summary.txt)

## Executive result

The existing evaluation framework completed a same-condition comparison of `basic`, `structured`, and `context_feedback` on the same four non-blocked cases: command injection, SQL injection, XSS, and insecure deserialization. Every strategy validated all four cases under the configured patch, test, rescan, and integrity gates.

**Hardcoded credentials remains BLOCKED.** Its separate structured workflow produced three invalid JSON Gemini responses, generated no candidate, ran no candidate tests, and did not run a security rescan. It was intentionally excluded from the controlled strategy batch and must not be counted as a successful repair.

The comparison is a small, single-run-per-case/strategy experiment. It does not show that one strategy is generally superior, and it does not establish a result for the excluded credential case.

## Controlled comparison protocol

- Four case directories were copied from `datasets/phase3` into a temporary evaluation input directory. The credential case was not copied or retried.
- Each strategy ran on those same four cases through `securefix.main evaluate`.
- Model, rule configurations, test timeout, and maximum attempt bound were held constant: `gemini-3.5-flash-lite`, `p/security-audit` plus the SQL/XSS/credential custom rules, 180-second test timeout, and up to three attempts.
- Every case had the same acceptance tests and Semgrep before/after checks across strategies. Tests ran in the workflow's Bubblewrap isolated workspace with network access disabled.
- `basic`, `structured`, and `context_feedback` identify each workflow's initial strategy. The shared workflow policy uses `context_feedback` for attempts after the first, regardless of the initial strategy.
- All 12 evaluated case/strategy workflows completed. Two initial `basic` generations (command injection and SQL injection) returned invalid JSON; both were recorded as failed attempts and recovered on the bounded context-feedback retry. No network, quota, or provider-connectivity error occurred in this controlled batch.
- Token totals include both failed and successful generation attempts. Candidate generation, test, rescan, and original-source-integrity outcomes are recorded in the machine-readable report.
- `project_revision` is null in the evaluation JSON because the controlled inputs were temporary copies rather than a Git worktree. The original vulnerable application files were not edited.

To repeat the same four-case experiment, create a fresh temporary directory, copy only the four non-blocked case directories, and use a new report directory. This consumes live Gemini quota:

```bash
TMP_DIR=$(mktemp -d /tmp/securefix-four-case-evaluation.XXXXXX)
cp -a datasets/phase3/command_injection datasets/phase3/sql_injection \
  datasets/phase3/xss datasets/phase3/insecure_deserialization "$TMP_DIR/"
python -m securefix.main evaluate "$TMP_DIR" \
  --strategies basic structured context_feedback \
  --max-attempts 3 \
  --model gemini-3.5-flash-lite \
  --config p/security-audit \
  --config datasets/phase3/sql_injection/securefix_sql_injection.yml \
  --config datasets/phase3/xss/securefix_xss.yml \
  --config datasets/phase3/hardcoded_key_demo/securefix_hardcoded_credential.yml \
  --output-dir reports/phase3-comparison-rerun
```

Do not add `datasets/phase3/hardcoded_key_demo` to this evaluation input unless a new credential-case attempt is explicitly intended. Use a new `--output-dir` for every evaluation; existing reports are not overwritten.

## Strategy-level metrics

Rates below use four cases per strategy. The framework's test-pass rate is passed pytest runs divided by completed pytest runs. Its vulnerability-removal rate is clean completed rescans where the selected finding was not rediscovered; neither metric alone proves remediation.

| Strategy | Validated repairs / patch success | Patch applications | Test runs passed | Acceptance tests | Clean rescans | New findings | Mean attempts / case | Tokens total / mean per case | Mean workflow time / case |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `basic` | 4/4 (100%) | 4/4 (100%) | 4/4 (100%) | 23/23 passed | 4/4 (100%) | 0 | 1.50 | 7,609 / 1,902.25 | 23.381272 s |
| `structured` | 4/4 (100%) | 4/4 (100%) | 4/4 (100%) | 23/23 passed | 4/4 (100%) | 0 | 1.00 | 5,278 / 1,319.50 | 13.853424 s |
| `context_feedback` | 4/4 (100%) | 4/4 (100%) | 4/4 (100%) | 23/23 passed | 4/4 (100%) | 0 | 1.00 | 5,044 / 1,261.00 | 12.900144 s |

The times and token counts are measured by the evaluation/workflow reports. Token totals include the Gemini input and output usage returned by the provider. No values were estimated. The complete controlled evaluation took 200.544557 seconds according to the framework report.

## Results by case and strategy

`Tests` are `passed/failed/skipped` on the final acceptance-test run for that case/strategy. `Tokens` are total measured tokens for the case. Each of the 12 cases was `VALIDATED`; each had one completed clean rescan, no new findings, and no scanner errors.

| Vulnerability | Strategy | Attempts | Tests | Tokens | Workflow seconds | Status |
|---|---|---:|---:|---:|---:|---|
| Command injection | `basic` | 2 | 13/0/0 | 2,891 | 31.857149 | VALIDATED |
| Command injection | `structured` | 1 | 13/0/0 | 1,496 | 15.658960 | VALIDATED |
| Command injection | `context_feedback` | 1 | 13/0/0 | 1,439 | 12.938343 | VALIDATED |
| SQL injection | `basic` | 2 | 4/0/0 | 2,388 | 30.454948 | VALIDATED |
| SQL injection | `structured` | 1 | 4/0/0 | 1,221 | 11.910753 | VALIDATED |
| SQL injection | `context_feedback` | 1 | 4/0/0 | 1,189 | 12.853032 | VALIDATED |
| XSS | `basic` | 1 | 3/0/0 | 1,085 | 12.138127 | VALIDATED |
| XSS | `structured` | 1 | 3/0/0 | 1,220 | 12.857511 | VALIDATED |
| XSS | `context_feedback` | 1 | 3/0/0 | 1,180 | 13.166913 | VALIDATED |
| Insecure deserialization | `basic` | 1 | 3/0/0 | 1,245 | 19.074862 | VALIDATED |
| Insecure deserialization | `structured` | 1 | 3/0/0 | 1,341 | 14.986471 | VALIDATED |
| Insecure deserialization | `context_feedback` | 1 | 3/0/0 | 1,236 | 12.642287 | VALIDATED |
| Hardcoded credentials | `basic` | Not run | Not run | Not measured | Not measured | **BLOCKED; excluded** |
| Hardcoded credentials | `structured` | Prior run: 3 | Not run | 3,696 | 11.567296 | **BLOCKED; three invalid JSON responses** |
| Hardcoded credentials | `context_feedback` | Not run independently | Not run | Not measured | Not measured | **BLOCKED; no independent comparison** |

The hardcoded-credential row's prior structured workflow includes two context-feedback retries, but these are retries within that blocked workflow, not an independent context-feedback evaluation.

## Five-category project outcome

The controlled strategy comparison deliberately excludes hardcoded credentials. Separately, the saved individual dataset workflows show four categories validated and one blocked:

| Category | Original finding | Final result | Tests / rescan evidence |
|---|---|---|---|
| Command injection | `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true`, `app.py:8`, ERROR | VALIDATED | 13 passed; 1 rescan, original finding absent, 0 new findings, 0 scanner errors |
| SQL injection | `datasets.phase3.sql_injection.securefix.python.sql-injection.string-interpolation`, `app.py:2`, ERROR | VALIDATED | 4 passed; 1 rescan, original finding absent, 0 new findings, 0 scanner errors |
| XSS | `datasets.phase3.xss.securefix.python.xss.unescaped-html-interpolation`, `app.py:2`, ERROR | VALIDATED | Final attempt 3 passed; earlier candidate failed 2 tests; completed rescans reported 0 new findings and 0 scanner errors |
| Hardcoded credentials | `datasets.phase3.hardcoded_key_demo.securefix.python.hardcoded-credential.api-key-literal`, `app.py:1`, WARNING | **BLOCKED** | Three invalid JSON responses; no candidate tests or rescan |
| Insecure deserialization | `python.lang.security.deserialization.pickle.avoid-pickle`, `app.py:5`, WARNING | VALIDATED | 3 passed; 1 rescan, original finding absent, 0 new findings, 0 scanner errors |

The credential-like value in that fixture is explicitly a dummy example, not a confirmed live credential.

## Failed and unavailable runs

- The blocked hardcoded-credential workflow is saved at [workflow-report.json](./hardcoded_credentials_adversarial/securefix-run-248aaa8d1d9c44818fc5df6117709b32/workflow-report.json). Each of its three attempts reported `LLM response is not valid JSON`. No candidate was generated or applied, and tests/rescan were not run. Its recorded token total and duration are retained above, but are not repair success.
- A prior one-off `basic` command-injection attempt outside the controlled batch failed before generation with `Gemini request failed. Check connectivity, credentials, quota, and model availability.` It produced no candidate, tests, rescan, or token metadata and is excluded from the controlled basic metrics.
- In the controlled batch, the `basic` command-injection and SQL-injection runs each had one invalid-JSON first attempt. The framework retried both with `context_feedback`; their successful final test/rescan results are included, and the failed attempts remain counted in tokens, latency, and attempts.
- The controlled batch itself had no failed or inconclusive case runs. An earlier interrupted all-case evaluation produced no completed evaluation report and is not included.
- The separately saved XSS workflow's first candidate failed 2 of 3 tests; the second attempt passed all 3 and was validated. See [XSS workflow report](./xss_adversarial/securefix-run-a692a701cefa439288d089d27102ce1c/workflow-report.json).

## Standalone structured-workflow aggregates across all five cases

These are descriptive aggregates from the separate per-category reports, not the controlled strategy comparison above. They include the blocked credential workflow in the denominator and keep its failed generation attempts visible:

- Validated repairs: **4/5 cases (80%)**.
- Candidate test runs: **4/5 passed, 1/5 failed**. Across individual executed acceptance tests: **24 passed, 2 failed, 0 skipped**.
- Candidate patches generated and applied in copies: **5/5 generated candidates applied**; one XSS candidate failed functional tests before a successful retry.
- Completed clean Semgrep rescans: **5/5**; this includes the first XSS candidate whose tests failed. The credential case had no rescan.
- Mean attempts: **1.6 per case** (8 total across five workflows).
- Recorded tokens: **10,387 total; 2,077.4 mean per case**.
- Processing time: **64.930753 seconds total; 12.986151 mean per case**.

The 80% validated-case rate is the meaningful all-five repair outcome; the 100% finding-removal rate on completed rescans must not be read as a 100% repair rate.

## Saved reports and limitations

- Controlled comparison: [evaluation JSON](./phase3-comparison-20261102/evaluation-report.json) and [summary](./phase3-comparison-20261102/evaluation-summary.txt).
- Individual validated runs: [command injection](./command_injection_adversarial/securefix-run-3a81110509fc411bb1e10374c11b7eaf/workflow-report.json), [SQL injection](./sql_injection_adversarial/securefix-run-7d716c766e7143dbad753a0ef28bc8aa/workflow-report.json), [XSS](./xss_adversarial/securefix-run-a692a701cefa439288d089d27102ce1c/workflow-report.json), and [insecure deserialization](./insecure_deserialization_adversarial/securefix-run-5c40384a92e5426785f088527a03fc30/workflow-report.json).
- Blocked credential run: [workflow report](./hardcoded_credentials_adversarial/securefix-run-248aaa8d1d9c44818fc5df6117709b32/workflow-report.json).

All strategy results are evidence from the configured benchmark tests and Semgrep rules, not a proof of security. Results are stochastic and based on one run for each of the 12 controlled pairs. The credential case requires a separately authorized follow-up after the invalid-JSON issue is addressed; this report does not retry or validate it.
