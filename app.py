"""Streamlit entry point for the SecureFix AI web interface."""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import streamlit as st

from ui.service import (
    MAX_ARCHIVE_BYTES,
    MAX_REPAIR_ATTEMPTS,
    REPORTS_ROOT,
    SUPPORTED_PROMPT_STRATEGIES,
    SUPPORTED_SEMGREP_CONFIGS,
    ArchiveValidationError,
    ExecutionResult,
    ReportRecord,
    attempt_display_status,
    dashboard_metrics,
    existing_patch_artifacts,
    finding_cwe_identifiers,
    finding_vulnerability_name,
    inspect_zip_archive,
    load_reports,
    read_report_artifact,
    repair_prerequisite_messages,
    run_uploaded_project,
    short_run_identifier,
    status_badge_class,
)


st.set_page_config(
    page_title="SecureFix AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

_STYLE = """
<style>
:root {
  --sf-bg: #0b1017;
  --sf-panel: #111a24;
  --sf-border: #243444;
  --sf-muted: #9aabba;
  --sf-text: #e8eef4;
  --sf-accent: #65e6bf;
}
.stApp { background: var(--sf-bg); color: var(--sf-text); }
.block-container { padding-top: 2rem; padding-bottom: 3rem; max-width: 1440px; }
[data-testid="stSidebar"] { background: #0e1620; border-right: 1px solid var(--sf-border); }
[data-testid="stSidebar"] > div:first-child { padding-top: 1.4rem; }
h1, h2, h3 { letter-spacing: -0.025em; }
h1 { font-weight: 650; }
[data-testid="stMetric"] {
  background: var(--sf-panel); border: 1px solid var(--sf-border);
  border-radius: 12px; padding: 1rem 1.1rem;
}
[data-testid="stMetricLabel"] { color: var(--sf-muted); }
[data-testid="stMetricValue"] { color: var(--sf-text); }
.sf-kicker { color: var(--sf-accent); text-transform: uppercase; letter-spacing: .13em;
  font-size: .73rem; font-weight: 700; }
.sf-subtitle { color: var(--sf-muted); font-size: 1.04rem; margin-top: -.45rem; }
.sf-panel { background: var(--sf-panel); border: 1px solid var(--sf-border);
  border-radius: 12px; padding: 1rem 1.15rem; }
.sf-status { display: inline-block; border-radius: 999px; padding: .25rem .65rem;
  font: 700 .72rem/1.4 sans-serif; letter-spacing: .06em; border: 1px solid;
  white-space: normal; overflow-wrap: anywhere; max-width: 100%; vertical-align: middle; }
.sf-status-validated { color: #75ecc2; background: #12362f; border-color: #246451; }
.sf-status-blocked { color: #ffd078; background: #382d17; border-color: #70531e; }
.sf-status-failed { color: #ff9a9a; background: #3a2024; border-color: #71323b; }
.sf-status-completed { color: #9dbcfb; background: #192b47; border-color: #314d77; }
.sf-status-incomplete { color: #d3b6ff; background: #2b2040; border-color: #554078; }
.sf-status-unknown { color: #c1ccd6; background: #202a34; border-color: #3b4b5a; }
.sf-note { border-left: 3px solid var(--sf-accent); padding: .7rem .9rem;
  background: #101c25; color: #c9d5df; border-radius: 0 8px 8px 0; }
.sf-stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(205px, 1fr));
  gap: .8rem; margin: 1.15rem 0 .45rem; }
.sf-stat-card { min-width: 0; min-height: 112px; box-sizing: border-box;
  background: var(--sf-panel); border: 1px solid var(--sf-border);
  border-radius: 12px; padding: 1rem 1.1rem; overflow-wrap: anywhere; }
.sf-stat-label { color: var(--sf-muted); font-size: .86rem; line-height: 1.35; }
.sf-stat-value { color: var(--sf-text); font-size: clamp(1.65rem, 2.4vw, 2.25rem);
  font-weight: 650; line-height: 1.2; margin-top: .55rem; }
.sf-stat-help { color: var(--sf-muted); font-size: .75rem; line-height: 1.35; margin-top: .3rem; }
.sf-record { min-width: 0; overflow-wrap: anywhere; padding: .2rem 0; }
.sf-code-note { color: var(--sf-muted); font-size: .82rem; margin-bottom: .35rem; }
.sf-progress { color: var(--sf-muted); line-height: 1.8; overflow-wrap: anywhere; }
.sf-metadata { overflow-wrap: anywhere; }
div[data-testid="stCode"] { max-width: 100%; }
div[data-testid="stExpander"] { border-color: var(--sf-border); border-radius: 10px; }
div.stButton > button[kind="primary"] { border: 0; font-weight: 650; }
@media (max-width: 760px) {
  .block-container { padding: 1rem 1rem 2rem; }
  [data-testid="stMetric"] { padding: .7rem; }
  .sf-stat-grid { grid-template-columns: repeat(auto-fit, minmax(155px, 1fr)); gap: .55rem; }
  .sf-stat-card { min-height: 100px; padding: .8rem; }
  .sf-stat-value { font-size: 1.65rem; }
}
@media (max-width: 520px) {
  .sf-stat-grid { grid-template-columns: 1fr 1fr; }
  .sf-stat-label { font-size: .78rem; }
  .sf-stat-card { min-height: 96px; padding: .7rem; }
}
</style>
"""
st.markdown(_STYLE, unsafe_allow_html=True)


def main() -> None:
    st.sidebar.markdown(
        '<div class="sf-kicker">Security engineering</div>'
        "<h2 style='margin:.3rem 0 0'>SecureFix AI</h2>"
        "<p style='color:#9aabba;margin-top:.25rem'>"
        "Autonomous Vulnerability Detection and Self-Verified Repair</p>",
        unsafe_allow_html=True,
    )
    page = st.sidebar.radio(
        "Workspace",
        (
            "Dashboard",
            "Source Code Analysis",
            "Vulnerability Results",
            "AI Repair",
            "Verification",
            "Reports",
        ),
        label_visibility="collapsed",
    )
    st.sidebar.divider()
    st.sidebar.caption(
        "A finding is scanner evidence, not proof of exploitability. "
        "Validated means configured checks passed—not guaranteed security."
    )

    records, report_errors = load_reports()
    if report_errors:
        st.sidebar.warning(f"{len(report_errors)} report file(s) could not be loaded.")

    if page == "Dashboard":
        _render_dashboard(records, report_errors)
    elif page == "Source Code Analysis":
        _render_analysis()
    elif page == "Vulnerability Results":
        _render_findings(records)
    elif page == "AI Repair":
        _render_repair(records)
    elif page == "Verification":
        _render_verification(records)
    else:
        _render_reports(records, report_errors)


def _render_header(kicker: str, title: str, subtitle: str) -> None:
    st.markdown(f'<div class="sf-kicker">{html.escape(kicker)}</div>', unsafe_allow_html=True)
    st.title(title)
    st.markdown(f'<p class="sf-subtitle">{html.escape(subtitle)}</p>', unsafe_allow_html=True)


def _render_stat_cards(cards: list[tuple[str, object, str]]) -> None:
    markup = ['<div class="sf-stat-grid">']
    for label, value, explanation in cards:
        markup.append(
            '<div class="sf-stat-card"><div class="sf-stat-label">'
            f"{html.escape(label)}</div><div class=\"sf-stat-value\">"
            f"{html.escape(str(value))}</div><div class=\"sf-stat-help\">"
            f"{html.escape(explanation)}</div></div>"
        )
    markup.append("</div>")
    st.markdown("".join(markup), unsafe_allow_html=True)


def _render_dashboard(records: list[ReportRecord], report_errors: list[str]) -> None:
    _render_header(
        "Operational overview",
        "SecureFix AI",
        "Autonomous Vulnerability Detection and Self-Verified Repair.",
    )
    metrics = dashboard_metrics(records, report_error_count=len(report_errors))
    _render_stat_cards(
        [
            ("Scan runs", metrics.scan_runs, "Scan-only runs; repair workflows counted separately."),
            ("Findings reported", metrics.findings_reported, "Finding records across saved scan and workflow reports; not unique issues."),
            ("Repairs validated", metrics.repairs_validated, "Only workflows with validation evidence and preserved-source status."),
            ("Blocked or failed", metrics.repairs_blocked_or_failed, "Classified workflow outcomes only; incomplete or unknown runs excluded."),
        ]
    )
    st.caption(
        f"Repair workflow runs (separate from scan runs): {metrics.workflow_runs} · "
        f"Incomplete reports: {metrics.incomplete_reports} · "
        f"Unknown workflow outcomes: {metrics.unknown_workflows}"
    )
    if not records and not report_errors:
        st.info("No reports are available yet. Upload a project to create the first scan.")
    elif report_errors:
        st.warning(
            f"{len(report_errors)} malformed, missing, or unreadable report(s) "
            "were excluded from the dashboard totals."
        )

    left, right = st.columns([1.2, 1])
    with left:
        st.subheader("Recent scan activity")
        activity = [
            record
            for record in records
            if record.kind in {"Scan", "Workflow", "Interface run"}
        ][:6]
        if not activity:
            st.info("No scan reports yet. Upload a project to begin.")
        for record in activity:
            finding_count = _report_finding_count(record)
            status = record.status or "UNKNOWN"
            st.markdown(
                f'<div class="sf-record"><strong>{html.escape(record.kind)}</strong> · '
                f'{html.escape(record.title)}<br><span class="sf-code-note">'
                f'{html.escape(short_run_identifier(record))} · '
                f'{html.escape(_format_timestamp(record.generated_at))} · '
                f'{finding_count} finding(s)</span> {_status_badge(status)}</div>',
                unsafe_allow_html=True,
            )
            st.divider()
    with right:
        st.subheader("Latest workflow results")
        workflows = [record for record in records if record.kind == "Workflow"]
        interface_repairs = [
            record
            for record in records
            if record.kind == "Interface run" and record.data.get("action") == "run"
        ]
        if not workflows and not interface_repairs:
            st.info("No repair workflows have been recorded.")
        for record in sorted(
            workflows + interface_repairs,
            key=lambda item: item.generated_at,
            reverse=True,
        )[:5]:
            st.markdown(
                f'<div class="sf-record"><strong>{html.escape(record.title)}</strong><br>'
                f'<span class="sf-code-note">{html.escape(short_run_identifier(record))} · '
                f'{html.escape(_format_timestamp(record.generated_at))}</span> '
                f'{_status_badge(record.status or "UNKNOWN")}</div>',
                unsafe_allow_html=True,
            )
            if record.kind == "Workflow":
                st.caption(
                    f"Attempts: {len(record.data.get('attempts', []))} · "
                    f"Strategy: {record.data.get('strategy', 'unknown')}"
                )
            elif record.kind == "Interface run" and record.data.get("error"):
                st.text(record.data.get("error", "Workflow did not start."))
            st.divider()
    st.markdown(
        '<div class="sf-note">VALIDATED records indicate that the configured '
        "patch, test, rescan, and source-integrity checks passed. They are not a "
        "guarantee that the application is vulnerability-free.</div>",
        unsafe_allow_html=True,
    )


def _render_analysis() -> None:
    _render_header(
        "Analysis workspace",
        "Source Code Analysis",
        "Validate a project archive, inspect its file list, and run SecureFix's existing scanner or isolated repair workflow.",
    )
    st.markdown(
        '<div class="sf-note">Uploaded code is extracted into a temporary directory. '
        "SecureFix scans it without modifying it; repair candidates are applied only "
        "to a disposable copy and verified using the existing sandbox.</div>",
        unsafe_allow_html=True,
    )
    uploaded = st.file_uploader("Upload a source project (.zip)", type=["zip"])
    summary = None
    contents: bytes | None = None
    if uploaded is not None:
        if uploaded.size > MAX_ARCHIVE_BYTES:
            st.error("The ZIP exceeds the 50 MiB upload limit.")
        else:
            contents = uploaded.getvalue()
            st.markdown(
                f"**Project archive:** {html.escape(uploaded.name)} · "
                f"{uploaded.size / (1024 * 1024):.2f} MiB",
                unsafe_allow_html=True,
            )
            try:
                summary = inspect_zip_archive(contents)
            except ArchiveValidationError as exc:
                st.error("The uploaded archive was rejected.")
                st.code(str(exc), language="text")
            else:
                st.success(
                    f"Archive validated · {len(summary.files)} file(s) · "
                    f"{summary.expanded_bytes / (1024 * 1024):.1f} MiB expanded"
                )
                with st.expander("Uploaded project structure", expanded=True):
                    shown = summary.files[:250]
                    st.code("\n".join(shown), language="text")
                    if len(summary.files) > len(shown):
                        st.caption(
                            f"Showing {len(shown)} of {len(summary.files)} files."
                        )

    configs = st.multiselect(
        "Semgrep configurations",
        options=SUPPORTED_SEMGREP_CONFIGS,
        default=[SUPPORTED_SEMGREP_CONFIGS[0]],
        format_func=lambda value: (
            "SecureFix SQL injection rule (local)"
            if value.endswith("/securefix_sql_injection.yml")
            else value
        ),
        help="Choose fixed Semgrep registry configurations or the checked-in SecureFix SQL rule. Arbitrary commands and uploaded rule files are not accepted.",
    )
    repair_col1, repair_col2 = st.columns([1, 1])
    with repair_col1:
        strategy = st.selectbox(
            "Repair prompt strategy",
            SUPPORTED_PROMPT_STRATEGIES,
            index=1,
            format_func=lambda value: {
                "basic": "Basic",
                "structured": "Structured",
                "context_feedback": "Context Feedback",
            }[value],
        )
    with repair_col2:
        attempts = st.number_input(
            "Maximum repair attempts",
            min_value=1,
            max_value=MAX_REPAIR_ATTEMPTS,
            value=3,
            step=1,
            help=f"The backend supports 1–{MAX_REPAIR_ATTEMPTS} attempts.",
        )
    consent = st.checkbox(
        "I understand selected finding context may be sent to the configured Gemini API during repair.",
        value=False,
    )
    repair_prerequisites = repair_prerequisite_messages()
    scan_prerequisites = tuple(
        message for message in repair_prerequisites if "Semgrep executable" in message
    )
    if scan_prerequisites:
        st.warning("Scan Only is unavailable until Semgrep is installed.")
        for message in scan_prerequisites:
            st.caption(message)
    if repair_prerequisites:
        st.warning("Repair verification prerequisites are not ready:")
        for message in repair_prerequisites:
            st.caption(message)

    scan_clicked, run_clicked = st.columns(2)
    can_start = contents is not None and summary is not None and bool(configs)
    with scan_clicked:
        scan_action = st.button(
            "Scan Only",
            disabled=not can_start or bool(scan_prerequisites),
            use_container_width=True,
        )
    with run_clicked:
        run_action = st.button(
            "Run Scan and Repair",
            type="primary",
            disabled=not can_start or not consent or bool(repair_prerequisites),
            use_container_width=True,
        )
    if contents is not None and summary is not None and not configs:
        st.warning("Select at least one Semgrep configuration.")
    if can_start and not consent:
        st.caption("Repair remains disabled until hosted-model data handling is acknowledged.")
    if contents is None:
        st.caption("Upload and validate a ZIP archive to enable either operation.")
    elif summary is not None and not configs:
        st.caption("Select at least one Semgrep configuration to enable scanning.")

    action = "scan" if scan_action else "run" if run_action else None
    if action is not None and contents is not None:
        try:
            with st.status(
                "SecureFix scan in progress…" if action == "scan" else
                "SecureFix repair workflow in progress…",
                expanded=True,
            ) as progress:
                st.markdown(
                    '<div class="sf-progress">Archive Validation → Semgrep Scan → '
                    + (
                        "Final Report"
                        if action == "scan"
                        else "Context Extraction → AI Repair → Functional Tests → "
                        "Security Rescan → Final Report"
                    )
                    + "</div>",
                    unsafe_allow_html=True,
                )
                st.caption(
                    "The existing CLI does not publish per-stage progress. "
                    "The completed report is the source of truth for stage results."
                )
                result = run_uploaded_project(
                    contents,
                    action=action,
                    configs=configs,
                    strategy=strategy,
                    maximum_attempts=int(attempts),
                )
                progress.update(
                    label=f"SecureFix {action} · {result.status}",
                    state="complete" if result.status in {"COMPLETED", "VALIDATED"} else "error",
                )
        except (ArchiveValidationError, OSError, ValueError) as exc:
            st.error("Unable to start SecureFix.")
            st.caption(str(exc))
        else:
            key = "latest_scan_result" if action == "scan" else "latest_workflow_result"
            st.session_state[key] = result
            _render_execution_result(result)

    latest = st.session_state.get("latest_scan_result")
    if not scan_clicked and isinstance(latest, ExecutionResult):
        st.subheader("Latest scan")
        _render_execution_result(latest)
    latest_workflow = st.session_state.get("latest_workflow_result")
    if not run_clicked and isinstance(latest_workflow, ExecutionResult):
        st.subheader("Latest repair workflow")
        _render_execution_result(latest_workflow)


def _render_execution_result(result: ExecutionResult) -> None:
    st.markdown(
        f"**Status:** {_status_badge(result.status)}",
        unsafe_allow_html=True,
    )
    if result.error:
        st.error("SecureFix could not complete this operation.")
        st.code(result.error, language="text")
    if result.report is not None:
        if result.action == "scan":
            scanner_errors = result.report.get("scanner_errors")
            st.caption(
                f"{_report_finding_count_from_data(result.report)} finding(s) · "
                f"{len(scanner_errors) if isinstance(scanner_errors, list) else 'Not available'} "
                "scanner error(s)"
            )
        elif result.status in {"VALIDATED", "BLOCKED", "FAILED"}:
            st.caption(
                "VALIDATED means configured workflow checks passed; it does not "
                "guarantee vulnerability-free software."
            )
    if result.report_path:
        st.caption(f"Report saved: {result.report_path.relative_to(REPORTS_ROOT.resolve())}")
    if result.stderr:
        with st.expander("SecureFix diagnostic output"):
            st.code(result.stderr, language="text")


def _render_findings(records: list[ReportRecord]) -> None:
    _render_header(
        "Semgrep output",
        "Vulnerability Results",
        "Inspect findings returned by Semgrep, including their locations, severities, and reported source context.",
    )
    st.warning(
        "These are static-analysis findings, not confirmed exploitable vulnerabilities. "
        "Reachability, attacker control, and runtime conditions require separate assessment."
    )
    sources = _finding_sources(records)
    if not sources:
        st.info("No saved scan findings are available yet. Run Scan Only or a repair workflow.")
        return
    record = _select_record("Finding report", sources, "findings_report")
    findings = _findings_for_record(record)
    if not findings:
        st.info("The selected report contains no findings.")
        return
    labels = [
        f"{finding_vulnerability_name(item)} · "
        f"{item.get('severity') or 'Not available'} · "
        f"{item.get('file_path') or 'Not available'}:{item.get('start_line') or '?'}"
        for item in findings
    ]
    index = st.selectbox(
        "Finding",
        range(len(findings)),
        format_func=lambda item: labels[item],
    )
    finding = findings[index]
    st.subheader(finding_vulnerability_name(finding))
    cwe_ids = finding_cwe_identifiers(finding)
    st.text(
        f"{', '.join(cwe_ids) if cwe_ids else 'CWE not available'}  |  "
        f"Semgrep rule: {finding.get('rule_id') or 'Not available'}"
    )
    _render_stat_cards(
        [
            ("Severity", str(finding.get("severity") or "Not available"), "Value reported by Semgrep."),
            ("File", str(finding.get("file_path") or "Not available"), "Path reported by Semgrep."),
            ("Line", finding.get("start_line") if finding.get("start_line") is not None else "Not available", "Start line reported by Semgrep."),
        ]
    )
    st.markdown("**Description**")
    description = finding.get("message")
    st.text(description if isinstance(description, str) and description else "Not available")
    st.markdown("**Relevant source-code context**")
    context = finding.get("context")
    context_lines = context.get("lines") if isinstance(context, dict) else None
    if isinstance(context_lines, list) and context_lines:
        source_lines = [
            str(line.get("content", ""))
            for line in context_lines
            if isinstance(line, dict)
        ]
        st.code(
            "\n".join(source_lines),
            language=_language_for_path(str(finding.get("file_path") or "")),
            line_numbers=True,
        )
        st.caption(
            f"Context starts at source line {context.get('start_line', 'Not available')}; "
            "line numbers inside the code block are excerpt-relative."
        )
    elif isinstance(finding.get("matched_code"), str) and finding["matched_code"]:
        st.code(
            finding["matched_code"],
            language=_language_for_path(str(finding.get("file_path") or "")),
            line_numbers=True,
        )
    else:
        st.info("Source context not available in this report.")
    with st.expander("Original finding metadata"):
        st.json(finding)


def _render_repair(records: list[ReportRecord]) -> None:
    _render_header(
        "Candidate review",
        "AI Repair",
        "Review the original finding, model-generated proposal, attempt history, and exact unified diff.",
    )
    workflows = [record for record in records if record.kind == "Workflow"]
    if not workflows:
        st.info("No saved repair workflow reports are available.")
        return
    record = _select_record("Repair workflow", workflows, "repair_report")
    report = record.data
    attempts = report.get("attempts", [])
    if not isinstance(attempts, list):
        attempts = []
    st.markdown(
        f"**Workflow status:** {_status_badge(record.status or 'UNKNOWN')}  \n"
        f"**Prompt strategy:** `{report.get('strategy', 'unknown')}` · "
        f"**Attempts recorded:** {len(attempts)} / "
        f"{report.get('maximum_attempts', 'Not available')}",
        unsafe_allow_html=True,
    )
    st.caption(
        "Generated candidates are untrusted proposals. Gemini generation alone does not "
        "establish that a candidate is correct or secure."
    )
    if not attempts:
        st.info("No candidate attempts are included in this report.")
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        number = attempt.get("attempt", "?")
        validation_status = attempt_display_status(attempt)
        with st.expander(
            f"Attempt {number} · {attempt.get('strategy', 'unknown')} · {validation_status}",
            expanded=len(attempts) == 1,
        ):
            _render_attempt_repair(record, attempt)
    selected = report.get("selected_finding")
    if not attempts and isinstance(selected, dict):
        st.markdown("**Original finding source**")
        _render_source_snippet(selected, None)
    if report.get("error"):
        st.error("The workflow report contains an error.")
        st.code(report["error"], language="text")


def _render_attempt_repair(record: ReportRecord, attempt: dict[str, Any]) -> None:
    candidate_files = attempt.get("candidate_files")
    attempt_number = attempt.get("attempt")
    if not isinstance(attempt_number, int) or isinstance(attempt_number, bool) or attempt_number < 1:
        attempt_number = 1
    attempt_directory = f"attempt-{attempt_number:02d}"
    proposal: dict[str, Any] | None = None
    diff_text = ""
    diff_data: bytes | None = None
    if isinstance(candidate_files, dict):
        proposal_name = candidate_files.get("proposal")
        diff_name = candidate_files.get("unified_diff")
        if isinstance(proposal_name, str):
            try:
                proposal_data = read_report_artifact(
                    record.path, f"{attempt_directory}/{proposal_name}"
                )
                decoded = json.loads(proposal_data)
                proposal = decoded if isinstance(decoded, dict) else None
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                st.warning(f"Candidate proposal could not be loaded: {exc}")
        if isinstance(diff_name, str):
            try:
                diff_data = read_report_artifact(
                    record.path, f"{attempt_directory}/{diff_name}"
                )
                diff_text = diff_data.decode("utf-8")
            except (OSError, UnicodeDecodeError, ValueError) as exc:
                st.caption(f"Candidate diff unavailable: {exc}")
    selected = record.data.get("selected_finding")
    repair = proposal.get("repair") if isinstance(proposal, dict) else None
    raw_changes = repair.get("changes", []) if isinstance(repair, dict) else []
    changes = raw_changes if isinstance(raw_changes, list) else []
    original_code = "\n".join(
        change.get("original_code", "")
        for change in changes
        if isinstance(change, dict) and isinstance(change.get("original_code", ""), str)
    )
    st.markdown("**Original vulnerable source**")
    if original_code:
        first_change = next(
            (change for change in changes if isinstance(change, dict)),
            {},
        )
        if first_change.get("start_line") is not None:
            st.caption(
                f"Source excerpt begins at line {first_change['start_line']}; "
                "line numbers inside the excerpt are relative."
            )
        st.code(
            original_code,
            language=_language_for_path(
                str(repair.get("file_path", "") if isinstance(repair, dict) else "")
            ),
            line_numbers=True,
        )
    else:
        _render_source_snippet(
            selected if isinstance(selected, dict) else {},
            None,
        )
    if proposal is not None and isinstance(repair, dict):
        st.caption(
            f"Prompt strategy for this attempt: {attempt.get('strategy', 'Not available')}"
        )
        st.markdown("**Candidate summary**")
        st.text(repair.get("summary") or "Not available")
        st.markdown("**AI-generated candidate replacement**")
        st.warning(
            "This is untrusted AI-generated code. Even when the workflow reports "
            "VALIDATED, passing configured checks is not proof of security."
        )
        replacements = [
            change.get("replacement_code", "")
            for change in changes
            if isinstance(change, dict) and isinstance(change.get("replacement_code", ""), str)
        ]
        replacement_code = "\n".join(replacements)
        if replacement_code:
            st.caption(
                "Line numbers are relative to the replacement excerpt; review the "
                "unified diff for exact source locations."
            )
            st.code(
                replacement_code,
                language=_language_for_path(str(repair.get("file_path") or "")),
                line_numbers=True,
            )
        else:
            st.info("No replacement source is available.")
        with st.expander("Proposal analysis and limitations"):
            st.json(
                {
                    "analysis": proposal.get("analysis"),
                    "reasoning_summary": proposal.get("reasoning_summary"),
                    "limitations": proposal.get("limitations"),
                }
            )
    if diff_text:
        st.markdown("**Unified diff**")
        st.caption("Use the code block copy control to copy the patch.")
        st.code(diff_text, language="diff")
        if diff_data is not None:
            st.download_button(
                "Download candidate patch",
                data=diff_data,
                file_name=f"{short_run_identifier(record)}-attempt-{attempt_number:02d}.diff",
                mime="text/x-diff",
                key=f"ai_patch_{record.path}_{attempt_number}",
            )
    elif not proposal:
        st.info("No candidate patch was generated.")
    if attempt.get("generation_error"):
        st.caption("Candidate generation diagnostic")
        st.code(attempt["generation_error"], language="text")


def _render_verification(records: list[ReportRecord]) -> None:
    _render_header(
        "Evidence and integrity",
        "Verification",
        "Inspect functional tests, before-and-after Semgrep results, scanner errors, and original-source integrity.",
    )
    workflows = [record for record in records if record.kind == "Workflow"]
    if not workflows:
        st.info("No saved verification workflow reports are available.")
        return
    record = _select_record("Verification report", workflows, "verification_report")
    report = record.data
    st.markdown(
        f"**Workflow status:** {_status_badge(record.status or 'UNKNOWN')}",
        unsafe_allow_html=True,
    )
    st.caption(
        "VALIDATED means this run's configured checks passed; it is not a guarantee "
        "that all vulnerabilities are absent."
    )
    if report.get("error"):
        st.error("The workflow report contains an error.")
        st.code(report["error"], language="text")
    try:
        original_scan_bytes = read_report_artifact(record.path, "original-scan.json")
        original_scan = json.loads(original_scan_bytes)
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        original_scan = None
    if isinstance(original_scan, dict):
        scan_results = original_scan.get("scan_results")
        initial_errors = (
            scan_results.get("errors", [])
            if isinstance(scan_results, dict)
            else []
        )
        if initial_errors:
            st.error("The original Semgrep scan reported scanner errors.")
            st.json(initial_errors)
    original = report.get("original_findings", [])
    _render_stat_cards(
        [
            (
                "Before-patch findings",
                len(original) if isinstance(original, list) else "Not available",
                "Original findings recorded by the workflow report.",
            )
        ]
    )
    attempts = report.get("attempts", [])
    if not isinstance(attempts, list):
        attempts = []
    if not attempts:
        st.info("No candidate verification attempts were recorded.")
    for attempt in attempts if isinstance(attempts, list) else []:
        if not isinstance(attempt, dict):
            continue
        number = attempt.get("attempt", "?")
        validation = attempt.get("validation")
        if not isinstance(validation, dict):
            validation = {}
        with st.expander(
            f"Attempt {number} · {validation.get('status', 'INCOMPLETE')}",
            expanded=len(attempts) == 1,
        ):
            tests = attempt.get("tests")
            st.markdown("#### Functional tests")
            if isinstance(tests, dict):
                passed, failed, skipped = (
                    tests.get("passed"),
                    tests.get("failed"),
                    tests.get("skipped"),
                )
                _render_stat_cards(
                    [
                        ("Test status", tests.get("status") or "Not available", "Status reported by the isolated test runner."),
                        ("Passed", _unknown_or_number(passed), "Tests marked passed by pytest."),
                        ("Failed", _unknown_or_number(failed), "Tests marked failed by pytest."),
                        ("Skipped", _unknown_or_number(skipped), "Tests marked skipped by pytest."),
                    ]
                )
                if tests.get("error"):
                    st.error(tests["error"])
                if tests.get("stderr"):
                    with st.expander("Test execution errors"):
                        st.code(tests["stderr"], language="text")
                if tests.get("stdout"):
                    with st.expander("Test output"):
                        st.code(tests["stdout"], language="text")
            else:
                st.info("Functional tests were not run.")

            security = attempt.get("security_rescan")
            st.markdown("#### Security rescan")
            if isinstance(security, dict):
                rescan_results = security.get("scan_results")
                after_findings = (
                    rescan_results.get("results", [])
                    if isinstance(rescan_results, dict)
                    else None
                )
                after_count = (
                    len(after_findings) if isinstance(after_findings, list) else "Unavailable"
                )
                remaining = security.get("remaining_original_findings", [])
                introduced = security.get("introduced_findings", [])
                _render_stat_cards(
                    [
                        ("Rescan status", security.get("status") or "Not available", "Full status returned by the rescan."),
                        ("After-patch findings", after_count, "Findings in the actual after-patch Semgrep result."),
                        ("Original findings remaining", len(remaining) if isinstance(remaining, list) else "Not available", "Matches reported by the before/after comparison."),
                        ("New findings", len(introduced) if isinstance(introduced, list) else "Not available", "Findings introduced in the rescan comparison."),
                    ]
                )
                if security.get("scanner_errors"):
                    st.error("Semgrep reported scanner errors.")
                    st.json(security["scanner_errors"])
                if security.get("error"):
                    st.error("The security rescan did not complete successfully.")
                    st.code(security["error"], language="text")
                with st.expander("Before-and-after finding details"):
                    st.markdown("**Original findings**")
                    st.json(security.get("original_findings", []))
                    st.markdown("**After-patch Semgrep findings**")
                    st.json(after_findings if isinstance(after_findings, list) else [])
                    st.markdown("**Remaining original findings**")
                    st.json(remaining)
                    st.markdown("**Newly introduced findings**")
                    st.json(introduced)
            else:
                st.info("A security rescan was not completed.")

            integrity = attempt.get("original_integrity")
            if not isinstance(integrity, dict):
                integrity = report.get("integrity")
            preserved = integrity.get("preserved") if isinstance(integrity, dict) else None
            st.markdown(
                f"**Original source preserved:** {_format_truth(preserved)} · "
                f"**Attempt validation:** {_status_badge(attempt_display_status(attempt))} · "
                f"Backend status: {html.escape(str(validation.get('status') or 'Not available'))}",
                unsafe_allow_html=True,
            )
            reasons = validation.get("reasons", [])
            if reasons:
                st.markdown("**Validation summary**")
                for reason in reasons:
                    st.text(f"- {reason}")


def _render_reports(records: list[ReportRecord], errors: list[str]) -> None:
    _render_header(
        "Saved artifacts",
        "Reports",
        "Browse existing scan and workflow reports, inspect JSON, and download generated candidate patches.",
    )
    if errors:
        with st.expander("Reports that could not be loaded"):
            for error in errors:
                st.text(error)
    if not records:
        st.info("No JSON reports exist in the reports directory yet.")
        return
    record = _select_record("Saved report", records, "saved_report")
    st.markdown(
        f"**Type:** {html.escape(record.kind)} · **Status:** "
        f"{_status_badge(record.status) if record.status else 'Not available'}",
        unsafe_allow_html=True,
    )
    st.caption(
        f"Run {short_run_identifier(record)} · "
        f"{_format_timestamp(record.generated_at)}"
    )
    with st.expander("Full report metadata"):
        st.json(
            {
                "run_id": record.data.get("run_id") or record.path.stem,
                "report_path": str(record.path.relative_to(REPORTS_ROOT.resolve())),
                "generated_at": record.generated_at,
                "report_type": record.kind,
                "workflow_status": record.status,
            }
        )
    report_bytes = read_report_artifact(record.path, record.path.name)
    st.download_button(
        "Download JSON report",
        data=report_bytes,
        file_name=record.path.name,
        mime="application/json",
        key="download_report",
    )
    with st.expander("JSON report details", expanded=True):
        st.json(record.data)

    if record.kind == "Workflow":
        for artifact in existing_patch_artifacts(record):
            st.download_button(
                f"Download attempt {artifact.attempt} patch",
                data=artifact.contents,
                file_name=f"{short_run_identifier(record)}-attempt-{artifact.attempt:02d}.diff",
                mime="text/x-diff",
                key=f"download_patch_{record.path}_{artifact.attempt}",
            )
    if record.kind == "Scan":
        st.caption(f"Findings: {_report_finding_count(record)}")
    elif record.kind == "Workflow":
        st.caption(
            f"Validation summary: {_status_explanation(record.status or 'UNKNOWN')}"
        )
    elif record.data.get("error"):
        st.error("The saved interface run contains an error.")
        st.code(record.data["error"], language="text")


def _finding_sources(records: list[ReportRecord]) -> list[ReportRecord]:
    return [
        record
        for record in records
        if record.kind == "Scan"
        or (record.kind == "Workflow" and isinstance(record.data.get("original_findings"), list))
    ]


def _findings_for_record(record: ReportRecord) -> list[dict[str, Any]]:
    data = record.data.get("findings")
    if record.kind == "Workflow":
        data = record.data.get("original_findings")
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _select_record(
    label: str,
    records: list[ReportRecord],
    session_key: str,
) -> ReportRecord:
    options = list(range(len(records)))
    selected = st.selectbox(
        label,
        options,
        format_func=lambda index: (
            f"{records[index].title} · {short_run_identifier(records[index])} · "
            f"{_format_timestamp(records[index].generated_at)}"
        ),
        key=session_key,
    )
    return records[selected]


def _render_source_snippet(finding: dict[str, Any], original_code: str | None) -> None:
    if original_code:
        st.code(original_code, language=_language_for_path(str(finding.get("file_path") or "")))
    elif finding.get("matched_code"):
        st.code(
            finding["matched_code"],
            language=_language_for_path(str(finding.get("file_path") or "")),
        )
    else:
        st.info("The saved report does not include the original source snippet.")


def _report_finding_count(record: ReportRecord) -> int:
    return _report_finding_count_from_data(record.data)


def _report_finding_count_from_data(data: dict[str, Any]) -> int:
    findings = data.get("findings")
    if not isinstance(findings, list):
        findings = data.get("original_findings")
    return (
        sum(isinstance(finding, dict) for finding in findings)
        if isinstance(findings, list)
        else 0
    )


def _status_badge(status: str) -> str:
    escaped = html.escape(status.upper())
    style = status_badge_class(status)
    return f'<span class="sf-status sf-status-{style}">{escaped}</span>'


def _status_explanation(status: str) -> str:
    if status == "VALIDATED":
        return "Configured workflow checks passed; this does not guarantee vulnerability-free software."
    if status == "BLOCKED":
        return "Required inputs or prerequisites prevented candidate validation."
    if status == "FAILED":
        return "A candidate or one or more configured validation checks did not pass."
    if status == "INCOMPLETE":
        return "The report lacks sufficient evidence to classify the workflow outcome."
    return "The report status is unknown and is not classified as validated, blocked, or failed."


def _unknown_or_number(value: Any) -> int | str:
    return value if isinstance(value, int) and not isinstance(value, bool) else "Unknown"


def _format_truth(value: Any) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unknown"


def _format_timestamp(value: str) -> str:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return timestamp.astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return value


def _language_for_path(path: str) -> str | None:
    suffix = Path(path).suffix.lower().lstrip(".")
    return {"py": "python", "js": "javascript", "ts": "typescript", "sh": "bash"}.get(
        suffix, suffix or None
    )


if __name__ == "__main__":
    main()
