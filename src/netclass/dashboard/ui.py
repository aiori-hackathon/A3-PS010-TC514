"""The Streamlit page. Presentation only: every decision comes from ``logic`` and the existing
``ClassificationService`` / ``AuditStore``.

Nothing runs at import time. ``main()`` is called by ``app.py``; it builds widgets and reads
configuration, and starts a lookup ONLY when the user presses the Classify button.
Evidence text is untrusted: it is shown in tables or plain text, never as HTML or markdown.
"""
from __future__ import annotations

import streamlit as st

from . import logic

LAST_OUTCOME_KEY = "ps010_last_outcome"
PROJECT_NAME = "Viltrumites — PS-010 IP Classification"


def _notice(level: str, text: str) -> None:
    {"success": st.success, "warning": st.warning, "info": st.info, "error": st.error}[level](text)


def _header(settings, diag: logic.Diagnostics) -> None:
    st.title(PROJECT_NAME)
    st.caption(
        f"Dashboard · package {diag.app_version} · policy {diag.policy_version} · "
        f"service {diag.service_version} · runs locally"
    )
    st.info(logic.DISCLAIMER)
    with st.expander("What the three labels mean"):
        for label in ("Known Tor exit", "Known hosted VPN/proxy endpoint", "Unknown"):
            st.markdown(f"**{label}**")
            st.text(logic.LABEL_EXPLANATIONS[label])
    # Visible status of optional pieces.
    if not diag.ipinfo_configured:
        st.caption("IPinfo Lite is not configured (optional; context only). It will not be used.")
    st.caption("Audit recording is OFF unless you opt in for a classification (Classify tab).")
    if diag.history.state is logic.HistoryState.UNAVAILABLE:
        st.warning("Audit history is unavailable: " + diag.history.message)


def _classify_section(settings, diag: logic.Diagnostics) -> None:
    st.header("Classify an IP address")
    raw_ip = st.text_input(
        "IPv4 or IPv6 address",
        key="ps010_ip_input",
        max_chars=64,
        placeholder="e.g. 8.8.8.8 or 2001:4860:4860::8888",
    )
    live = logic.check_ip_input(raw_ip) if raw_ip.strip() else None
    if live is not None:  # local validation only: no network, no classification
        if live.status is logic.InputStatus.INVALID:
            st.error(live.message)
        elif live.status is logic.InputStatus.EXCLUDED:
            st.warning(live.message + " " + logic.COLLECTION_SKIPPED_NOTE)
        elif live.version == 6:
            st.caption(logic.IPV6_NOTE)

    st.subheader("Optional context (never changes the label)")
    want_ripestat = st.checkbox(
        "Also fetch RIPEstat network context",
        key="ps010_ripestat",
        help="Sends the IP address to RIPEstat (RIPE NCC). Context only.",
    )
    want_ipinfo = st.checkbox(
        "Also fetch IPinfo Lite metadata",
        key="ps010_ipinfo",
        disabled=not diag.ipinfo_configured,
        help=(
            "Sends the IP address to IPinfo. Context only."
            if diag.ipinfo_configured
            else "Disabled: no IPinfo token is configured."
        ),
    )

    st.subheader("Audit recording (optional, off by default)")
    wants_audit = st.checkbox(
        "Save this classification to the local audit history",
        key="ps010_audit_opt_in",
        value=False,
    )
    acknowledged = False
    if wants_audit:
        st.warning(
            "If you continue, the IP address you enter, the observation time, the label, the "
            "reason codes and the evidence/context fields allowed by the audit schema are "
            "written to a local SQLite file (created if it does not exist). IP addresses can be "
            "personal data. Tokens and raw response bodies are never stored. Records are deleted "
            f"only by a manual purge command (retention setting: {diag.retention_days} days"
            f"{'; 0 = kept indefinitely' if diag.retention_days == 0 else ''}). "
            "This dashboard has no purge button."
        )
        acknowledged = st.checkbox(
            "I understand and want this classification recorded locally",
            key="ps010_audit_ack",
            value=False,
        )
        if not acknowledged:
            st.caption("Nothing will be recorded until you tick the box above.")

    if st.button("Classify IP", type="primary", key="ps010_classify"):
        options = logic.ClassifyOptions(
            include_ripestat=want_ripestat,
            include_ipinfo=want_ipinfo and diag.ipinfo_configured,
            audit=logic.AuditChoice(wants_recording=wants_audit, acknowledged_privacy=acknowledged),
        )
        with st.spinner("Looking up evidence…"):
            st.session_state[LAST_OUTCOME_KEY] = logic.run_classification(
                raw_ip, options, settings=settings
            )

    outcome = st.session_state.get(LAST_OUTCOME_KEY)
    if outcome is not None:
        _show_outcome(outcome, settings)


def _show_outcome(outcome: logic.DashboardOutcome, settings) -> None:
    secrets = logic.settings_secrets(settings)
    st.divider()
    if outcome.error:
        st.error(outcome.error)
        return
    result = outcome.result
    c = result.classification
    if outcome.collection_skipped:
        st.warning("Collection skipped. " + (outcome.skipped_reason or ""))
    st.header(str(c.label))
    st.caption(
        f"{c.ip} · observed {c.observed_at.isoformat(timespec='seconds')} · "
        f"policy {c.policy_version} · service {result.service_version}"
    )
    st.text(logic.LABEL_EXPLANATIONS[c.label.value])
    st.markdown("**Reason code**")
    st.code(", ".join([c.reason_code.value, *[r.value for r in c.additional_reason_codes]]))
    st.markdown("**Explanation from the classifier**")
    st.text(logic.safe_text(c.explanation, secrets, 2000))
    for caveat in c.caveats:
        st.caption(logic.safe_text(caveat, secrets, 600))
    if outcome.check.version == 6:
        st.caption(logic.IPV6_NOTE)
    if c.label.value == "Unknown":
        st.info(
            "Unknown means the evidence did not support another label. It does not mean the "
            "address is safe, malicious, or definitely not a VPN, proxy or Tor exit."
        )

    st.subheader("Classification evidence")
    rows = logic.evidence_rows(result, secrets)
    if rows:
        st.dataframe(rows, hide_index=True)
    else:
        st.caption("No evidence sources were consulted for this address.")

    if result.ripestat_context is not None:
        st.subheader("RIPEstat — Context only — does not determine classification")
        st.dataframe(logic.ripestat_rows(result.ripestat_context, secrets), hide_index=True)
    if result.ipinfo_metadata is not None:
        st.subheader("IPinfo Lite — Context only — does not determine classification")
        st.dataframe(logic.ipinfo_rows(result.ipinfo_metadata, secrets), hide_index=True)

    if outcome.audit is not None:
        level, text = logic.audit_message(outcome.audit, settings)
        _notice(level, text)


def _history_section(settings, diag: logic.Diagnostics) -> None:
    st.header("Audit history")
    st.caption("Read-only view of the local audit database. Opening this section never creates it.")
    status = diag.history
    if status.state is not logic.HistoryState.READY:
        _notice("info" if status.state is logic.HistoryState.NO_DATABASE else "warning", status.message)
        return

    col1, col2, col3, col4 = st.columns(4)
    label_choice = col1.selectbox("Label", ["All", *logic.LABELS], key="ps010_h_label")
    ip_text = col2.text_input("Exact IP address", key="ps010_h_ip", max_chars=64)
    size = col3.selectbox(
        "Rows per page", logic.PAGE_SIZES, index=logic.PAGE_SIZES.index(logic.DEFAULT_PAGE_SIZE),
        key="ps010_h_size",
    )
    page = col4.number_input(
        "Page", min_value=1, max_value=logic.MAX_PAGE_NUMBER, value=1, step=1, key="ps010_h_page"
    )
    data = logic.read_history(
        settings,
        label=None if label_choice == "All" else label_choice,
        ip=ip_text,
        page=int(page),
        page_size=int(size),
    )
    if data.filter_error:
        st.error(data.filter_error)
        return
    if data.state is not logic.HistoryState.READY:
        _notice("warning", data.message)
        return
    if not data.rows:
        if data.page > 1:
            st.info("No records on this page. Try a lower page number.")
        else:
            st.info("The audit database is readable but contains no matching records.")
        return

    secrets = logic.settings_secrets(settings)
    st.dataframe(logic.history_table(data.rows, secrets), hide_index=True)
    st.caption(
        f"Page {data.page} · {len(data.rows)} record(s), newest first"
        + (" · more records on the next page" if data.has_next else "")
    )

    run_ids = [r["run_id"] for r in data.rows]
    chosen = st.selectbox("Show evidence and context for run", ["—", *run_ids], key="ps010_h_run")
    if chosen != "—":
        detail = logic.read_run_detail(settings, int(chosen))
        if detail is None:
            st.warning("That record could not be read.")
            return
        st.markdown("**Classification evidence (as recorded)**")
        ev = logic.detail_evidence_rows(detail, secrets)
        if ev:
            st.dataframe(ev, hide_index=True)
        else:
            st.caption("No evidence rows recorded.")
        ctx = logic.detail_context_rows(detail, secrets)
        if ctx:
            st.markdown("**Context metadata — context only, does not determine classification**")
            st.dataframe(ctx, hide_index=True)


def _diagnostics_section(diag: logic.Diagnostics) -> None:
    st.header("Source and database status")
    st.caption("Derived from configuration and local files only. No live lookup is made.")
    h = diag.history
    rows = [
        {"Item": "Package version", "Status": diag.app_version},
        {"Item": "Policy version", "Status": diag.policy_version},
        {"Item": "Service version", "Status": diag.service_version},
        {"Item": "Evidence sources enabled", "Status": ", ".join(diag.enabled_sources) or "none"},
        {"Item": "RIPEstat context", "Status": "available on request (off by default)"},
        {"Item": "IPinfo Lite context", "Status": "configured" if diag.ipinfo_configured else "not configured"},
        {
            "Item": "Audit recording",
            "Status": "per-classification opt-in only"
            + (" (environment flag is set, but the dashboard still asks)" if diag.audit_env_enabled else ""),
        },
        {"Item": "Audit database file", "Status": diag.database_file},
        {
            "Item": "Audit database state",
            "Status": {
                logic.HistoryState.READY: f"exists and readable ({h.runs} run(s), schema v{h.schema_version})",
                logic.HistoryState.NO_DATABASE: "does not exist (not created)",
                logic.HistoryState.UNAVAILABLE: "exists but unreadable",
            }[h.state],
        },
        {"Item": "Retention setting", "Status": f"{diag.retention_days} day(s) — {diag.retention_note}"},
    ]
    st.dataframe(rows, hide_index=True)


def main() -> None:
    st.set_page_config(page_title=PROJECT_NAME, page_icon="🛡️", layout="wide")
    settings, problem = logic.load_settings_safely()
    if settings is None:
        st.title(PROJECT_NAME)
        st.error(problem)
        return
    diag = logic.collect_diagnostics(settings)
    _header(settings, diag)
    tab_classify, tab_history, tab_status = st.tabs(["Classify", "Audit history", "Status"])
    with tab_classify:
        _classify_section(settings, diag)
    with tab_history:
        _history_section(settings, diag)
    with tab_status:
        _diagnostics_section(diag)
