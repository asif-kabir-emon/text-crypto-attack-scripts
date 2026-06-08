import io
import os
import sys
import tempfile
from contextlib import redirect_stdout

import pandas as pd
import streamlit as st
try:
    import plotly.express as px # pyright: ignore[reportMissingImports]
    PLOTLY_AVAILABLE = True
except Exception:
    px = None
    PLOTLY_AVAILABLE = False

# Import functions from your separate toolkit file
from zwc_attack_toolkit import (
    ZWC_CHARS,
    ZWC_MAP,
    attack_scan,
    attack_stats,
    attack_extract_raw,
    attack_strip,
    attack_noise,
    attack_substitute,
    decode_enhanced_with_key,
    attack_brute,
)

st.set_page_config(
    page_title="Zero-Width Steganography Analyzer & Attack Lab",
    page_icon="🕵️",
    layout="wide",
)

# --- Small visual improvements via CSS ---
st.markdown(
    """
    <style>
    .stApp { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial; }

    .title {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 0.35rem;
    }

    .title h1 {
        font-size: clamp(1.7rem, 3.4vw, 2.7rem);
        line-height: 1.1;
        margin: 0;
    }

    .metric-label { color: #6b7280; font-size:0.9rem }
    .card { background: #ffffff; padding: 12px; border-radius: 10px; box-shadow: 0 1px 3px rgba(16,24,40,0.05); }
    .small-muted { color:#6b7280; font-size:0.85rem }

    .stMetric {
        background: #ffffff;
        border: 1px solid rgba(148, 163, 184, 0.16);
        padding: 0.85rem 0.95rem;
        border-radius: 14px;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
    }

    .stMetric [data-testid="stMetricLabel"],
    .stMetric [data-testid="stMetricValue"],
    .stMetric [data-testid="stMetricDelta"] {
        color: #0f172a !important;
    }

    .stMetric [data-testid="stMetricLabel"] {
        opacity: 0.78;
        font-weight: 600;
    }

    .stMetric [data-testid="stMetricValue"] {
        font-size: 1.85rem;
        line-height: 1.1;
        font-weight: 700;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


def capture_print_output(func, *args, **kwargs):
    """Run an existing toolkit function and capture its printed output."""
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        result = func(*args, **kwargs)
    return buffer.getvalue(), result


def read_uploaded_text(uploaded_file):
    if uploaded_file is None:
        return ""
    return uploaded_file.getvalue().decode("utf-8", errors="replace")


def parse_passkey_candidates(raw_text):
    candidates = []
    seen = set()
    for line in raw_text.splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        if candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


def attack_brute_candidates(text, candidates):
    """Brute-force enhanced stego text using an in-memory candidate list."""
    print("============================================================")
    print("  ACTIVE ATTACK 8/9 — Passkey Brute-Force")
    print("============================================================")

    if not candidates:
        print("[ERROR] No passkey candidates provided.")
        return

    print(f"[INFO] Using {len(candidates)} provided passkey candidates.")
    print("[INFO] Attempting brute-force on enhanced ZWC stego text...\n")

    found = False
    for i, key in enumerate(candidates):
        result = decode_enhanced_with_key(text, key)
        if not result.startswith("[FAIL]") and not result.startswith("[ERROR]"):
            print(f"[!!] PASSKEY FOUND: '{key}'")
            print(f"[!!] Decoded message: {result}")
            found = True
            break
        if i % 10 == 0:
            print(f"     Tried {i+1}/{len(candidates)} keys...", end='\r')

    if not found:
        print(f"\n[RESULT] Passkey NOT found in provided candidates ({len(candidates)} attempts).")
        print("[RESULT] AES-256 + HMAC resists dictionary attacks. Full brute-force is infeasible.")


def zwc_summary(text):
    total_chars = len(text)
    zwc_total = sum(1 for ch in text if ch in ZWC_CHARS)
    visible_chars = total_chars - zwc_total
    ratio = zwc_total / visible_chars if visible_chars else 0
    return total_chars, visible_chars, zwc_total, ratio


def zwc_frequency_table(text):
    rows = []
    for ch, name in ZWC_MAP.items():
        count = text.count(ch)
        if count > 0:
            rows.append(
                {
                    "Unicode": f"U+{ord(ch):04X}",
                    "Name": name,
                    "Count": count,
                }
            )
    return pd.DataFrame(rows)


def zwc_position_stats(text):
    positions = [i for i, ch in enumerate(text) if ch in ZWC_CHARS]
    gaps = [positions[i + 1] - positions[i] for i in range(len(positions) - 1)] if len(positions) > 1 else []
    avg_gap = sum(gaps) / len(gaps) if gaps else 0
    return positions, gaps, avg_gap


def zwc_sequence_table(text, limit=500):
    rows = []
    for sequence_no, (position, ch) in enumerate(
        ((idx, ch) for idx, ch in enumerate(text) if ch in ZWC_CHARS),
        start=1,
    ):
        rows.append(
            {
                "Seq": sequence_no,
                "Position": position,
                "Unicode": f"U+{ord(ch):04X}",
                "Name": ZWC_MAP.get(ch, "Unknown ZWC"),
                "Python Escape": ch.encode("unicode_escape").decode("ascii"),
            }
        )

    return pd.DataFrame(rows[:limit])


def analyze_zwc_sequence_pattern(text):
    zwc_positions = [idx for idx, ch in enumerate(text) if ch in ZWC_CHARS]
    if len(zwc_positions) < 3:
        return {
            "verdict": "Not enough data",
            "confidence": 0.0,
            "details": "At least 3 ZWC characters are needed to estimate sequence behavior.",
            "anchor_coverage": 0.0,
            "avg_anchor_skip": 0.0,
            "gap_cv": 0.0,
        }

    visible_chars = []
    original_to_visible = {}
    visible_index = 0
    for original_index, ch in enumerate(text):
        if ch in ZWC_CHARS:
            continue
        original_to_visible[original_index] = visible_index
        visible_chars.append(ch)
        visible_index += 1

    visible_text = "".join(visible_chars)
    word_boundaries = [
        idx
        for idx in range(len(visible_text) - 1)
        if not visible_text[idx].isspace() and visible_text[idx + 1].isspace()
    ]
    boundary_rank = {visible_idx: rank for rank, visible_idx in enumerate(word_boundaries)}

    anchor_ranks = []
    last_visible_index = -1
    for original_index, ch in enumerate(text):
        if ch in ZWC_CHARS:
            if last_visible_index in boundary_rank:
                anchor_ranks.append(boundary_rank[last_visible_index])
        else:
            last_visible_index = original_to_visible[original_index]

    anchor_gaps = [anchor_ranks[i + 1] - anchor_ranks[i] for i in range(len(anchor_ranks) - 1)]
    consecutive_steps = sum(1 for gap in anchor_gaps if gap == 1)
    anchor_coverage = consecutive_steps / len(anchor_gaps) if anchor_gaps else 0.0
    avg_anchor_skip = sum(anchor_gaps) / len(anchor_gaps) if anchor_gaps else 0.0

    position_gaps = [zwc_positions[i + 1] - zwc_positions[i] for i in range(len(zwc_positions) - 1)]
    avg_gap = sum(position_gaps) / len(position_gaps)
    gap_variance = sum((gap - avg_gap) ** 2 for gap in position_gaps) / len(position_gaps)
    gap_cv = (gap_variance ** 0.5) / avg_gap if avg_gap else 0.0

    if anchor_coverage >= 0.75 and avg_anchor_skip <= 1.4:
        verdict = "Sequential-like"
        confidence = min(0.99, 0.55 + (anchor_coverage * 0.35) + max(0, 0.10 - gap_cv * 0.05))
        details = "Most ZWCs appear on consecutive word-boundary positions in the uploaded file."
    elif anchor_coverage <= 0.35 or avg_anchor_skip >= 2.0:
        verdict = "Random-like"
        confidence = min(0.99, 0.55 + ((1 - anchor_coverage) * 0.30) + min(avg_anchor_skip / 10, 0.14))
        details = "ZWCs skip many possible word-boundary positions, which looks like scattered/random placement."
    else:
        verdict = "Mixed / inconclusive"
        confidence = 0.50
        details = "The uploaded file has both consecutive and skipped ZWC placements."

    return {
        "verdict": verdict,
        "confidence": confidence,
        "details": details,
        "anchor_coverage": anchor_coverage,
        "avg_anchor_skip": avg_anchor_skip,
        "gap_cv": gap_cv,
    }


def render_zwc_sequence_view(text, source_label="uploaded file"):
    pattern = analyze_zwc_sequence_pattern(text)
    st.markdown("#### Calculated ZWC Sequence Pattern")
    verdict_col, confidence_col, coverage_col = st.columns(3)
    verdict_col.metric("Pattern", pattern["verdict"])
    confidence_col.metric("Confidence", f"{pattern['confidence'] * 100:.0f}%")
    coverage_col.metric("Consecutive coverage", f"{pattern['anchor_coverage'] * 100:.1f}%")
    st.caption(
        f"Source: {source_label} | {pattern['details']} "
        f"Average anchor skip: {pattern['avg_anchor_skip']:.2f}; gap variation: {pattern['gap_cv']:.2f}."
    )

    sequence_df = zwc_sequence_table(text)
    if sequence_df.empty:
        st.info("No known zero-width characters detected in the text.")
        return

    st.markdown("#### ZWC Sequence")
    st.caption(f"Source: {source_label} | Showing first {len(sequence_df)} ZWC characters in file order.")
    st.dataframe(sequence_df, use_container_width=True, height=260)
    st.code(" ".join(sequence_df["Unicode"].tolist()), language="text")


def render_brute_status(output):
    if "Passkey NOT found" in output:
        st.warning("Passkey NOT found in wordlist (25 attempts).")
    elif "PASSKEY FOUND" in output:
        st.success("Passkey found successfully.")
    elif "[ERROR]" in output:
        st.error("Brute-force finished with an error.")
    else:
        st.info("Brute-force completed.")


def render_active_attack_status(output, attack_name):
    if "[RESULT]" in output:
        st.success(f"{attack_name} completed successfully.")
    elif "[ERROR]" in output:
        st.error(f"{attack_name} finished with an error.")
    else:
        st.info(f"{attack_name} completed.")


def render_attack_metrics(source_text, result_text=None):
    total_chars, visible_chars, zwc_total, _ = zwc_summary(source_text)
    result_zwc_total = sum(1 for ch in result_text if ch in ZWC_CHARS) if result_text is not None else None

    metric_1, metric_2, metric_3 = st.columns(3)
    with metric_1:
        st.metric("Total characters", total_chars)
    with metric_2:
        st.metric("Visible characters", visible_chars)
    with metric_3:
        if result_zwc_total is None:
            st.metric("ZWC characters", zwc_total)
        else:
            st.metric("ZWC characters", result_zwc_total, delta=result_zwc_total - zwc_total)


st.markdown('<div class="title"><h1>🕵️ Zero-Width Steganography Analyzer & Attack Lab</h1></div>', unsafe_allow_html=True)
st.caption("Scan zero-width data, study embedding behavior, and explore attack options in one dashboard.")

with st.sidebar:
    st.subheader("Input & Options")
    uploaded_file = st.file_uploader("Upload stego text file", type=["txt", "text", "csv", "md"])
    st.divider()

    # Beautified actions list with emoji and short hints
    st.subheader("Actions")
    ACTION_LABELS = [
        "🔍 Scan",
        "📊 Statistics",
        "🔧 Raw Extract",
        "🔐 Decode with Known Passkey",
        "🧹 Strip Attack",
        "🌪️ Noise Attack",
        "🔁 Substitution Attack",
        "💣 Brute Force",
        "🧾 Full Passive Scan",
    ]

    action = st.radio("Choose operation", ACTION_LABELS, index=0)
    st.caption("Select an action; use the Run button below to execute it.")

    # Action descriptions
    ACTION_DESCRIPTIONS = {
        "🔍 Scan": "Detect presence and counts of zero-width characters.",
        "📊 Statistics": "Frequency and position analysis of ZWC characters.",
        "🔧 Raw Extract": "Extract raw bit sequences from baseline stego.",
        "🔐 Decode with Known Passkey": "Attempt enhanced decode using a known passkey (HMAC checked).",
        "🧹 Strip Attack": "Remove all ZWC characters (destroys hidden payload).",
        "🌪️ Noise Attack": "Inject random ZWC characters to corrupt payloads.",
        "🔁 Substitution Attack": "Replace original ZWCs with other invisibles to alter bits.",
        "💣 Brute Force": "Try candidates from a wordlist to recover passkey (enhanced).",
        "🧾 Full Passive Scan": "Run scan → stats → raw extraction and produce a report.",
    }

    with st.expander("Action details", expanded=False):
        st.write(ACTION_DESCRIPTIONS.get(action, ""))

    with st.expander("Advanced options", expanded=False):
        st.write("Noise density, brute-force wordlist, and other action-specific settings are available in the main panel when you run the action.")

if uploaded_file is not None:
    text = read_uploaded_text(uploaded_file)
    input_source_label = f"uploaded file: {uploaded_file.name}"
else:
    text = ""
    input_source_label = "no input"

if not text:
    st.info("Upload a text file in the sidebar to begin.")
    st.stop()

# col1, col2, col3, col4 = st.columns([1.5, 1, 1, 1])
# total_chars, visible_chars, zwc_total, ratio = zwc_summary(text)
# col1.metric("Total characters", total_chars, help="Total length including invisible characters")
# col2.metric("Visible characters", visible_chars)
# col3.metric("ZWC characters", zwc_total)
# col4.metric("ZWC / visible ratio", f"{ratio:.4f}")

# freq_df = zwc_frequency_table(text)
# if not freq_df.empty:
#     with st.container():
#         st.subheader("Detected ZWC characters")
#         left, right = st.columns([1, 2])
#         left.dataframe(freq_df, use_container_width=True, height=160)
#         # simple bar plot
#         if PLOTLY_AVAILABLE:
#             fig = px.bar(freq_df, x="Unicode", y="Count", text="Count", height=180)
#             fig.update_layout(margin=dict(l=0, r=0, t=10, b=10))
#             right.plotly_chart(fig, use_container_width=True)
#         else:
#             series = freq_df.set_index('Unicode')['Count']
#             right.bar_chart(series)
# else:
#     st.warning("No known zero-width characters detected.")

# st.divider()

# Normalize selected action key (strip emoji)
action_key = action.split(' ', 1)[1] if ' ' in action else action

# Prominent action header and run button
run_pressed = False
if action_key == "Scan":
    st.markdown("### Scan Overview")
    st.caption("Quick visual detection of zero-width characters and their distribution.")
    run_pressed = st.button(f"Run {action}", key="run_action")
else:
    st.markdown(f"### {action}")
    st.caption(ACTION_DESCRIPTIONS.get(action, ""))
    run_pressed = st.button(f"Run {action}", key="run_action")

st.write("")

def render_action_frame(title, caption, body_fn):
    st.markdown(f"### {title}")
    st.caption(caption)
    with st.container():
        body_fn()

if action_key == "Scan":
    if run_pressed:
        scanner_freq_df = zwc_frequency_table(text)
        total_chars, visible_chars, zwc_total, ratio = zwc_summary(text)

        scan_top_left, scan_top_mid, scan_top_right = st.columns([1, 1, 1])
        scan_top_left.metric("Total characters", total_chars)
        scan_top_mid.metric("Visible characters", visible_chars)
        scan_top_right.metric("ZWC / visible ratio", f"{ratio:.4f}")

        if not scanner_freq_df.empty:
            st.markdown("#### Visual Summary")
            chart_col, table_col = st.columns([1.75, 1])
            with chart_col:
                scan_fig = px.bar(
                    scanner_freq_df,
                    x="Unicode",
                    y="Count",
                    color="Name",
                    text="Count",
                    height=320,
                )
                scan_fig.update_layout(
                    margin=dict(l=0, r=0, t=20, b=0),
                    showlegend=False,
                    xaxis_title="Unicode Character",
                    yaxis_title="Count",
                )
                st.plotly_chart(scan_fig, use_container_width=True)

            with table_col:
                st.markdown("#### Detected Types")
                st.dataframe(scanner_freq_df, use_container_width=True, height=220)

            render_zwc_sequence_view(text, input_source_label)

        with st.expander("Raw detection report", expanded=True):
            output, _ = capture_print_output(attack_scan, text)
            st.code(output, language="text")

elif action_key == "Statistics":
    if run_pressed:
        st.markdown("### Statistical Snapshot")
        st.caption("Frequency, position, and payload indicators in a compact layout.")
        with st.container():
            stats_freq_df = zwc_frequency_table(text)
            positions, gaps, avg_gap = zwc_position_stats(text)
            total_zwc = int(stats_freq_df["Count"].sum()) if not stats_freq_df.empty else 0
            distinct_types = len(stats_freq_df)
            estimated_bits = total_zwc * 2 if distinct_types == 4 else total_zwc if distinct_types == 2 else 0
            estimated_bytes = estimated_bits // 8 if estimated_bits else 0

            top_left, top_mid, top_right = st.columns([1, 1, 1])
            top_left.metric("Total ZWC characters", total_zwc)
            top_mid.metric("Distinct ZWC types", distinct_types)
            top_right.metric("Estimated payload", f"~{estimated_bytes} bytes")

            if not stats_freq_df.empty:
                st.markdown("#### Visual Summary")
                chart_col, gap_col = st.columns([1.75, 1])
                with chart_col:
                    stat_fig = px.bar(
                        stats_freq_df,
                        x="Unicode",
                        y="Count",
                        color="Name",
                        text="Count",
                        height=320,
                    )
                    stat_fig.update_layout(
                        margin=dict(l=0, r=0, t=20, b=0),
                        showlegend=False,
                        xaxis_title="Unicode Character",
                        yaxis_title="Count",
                    )
                    st.plotly_chart(stat_fig, use_container_width=True)

                with gap_col:
                    st.markdown("#### Position Summary")
                    st.metric("First ZWC position", positions[0] if positions else "N/A")
                    st.metric("Last ZWC position", positions[-1] if positions else "N/A")
                    st.metric("Average gap", f"{avg_gap:.1f}" if gaps else "N/A")

                if gaps:
                    st.markdown("#### Gap Distribution")
                    gap_fig = px.histogram(
                        x=gaps,
                        nbins=min(20, max(5, len(gaps) // 10)),
                        labels={"x": "Gap size"},
                        title="",
                        height=260,
                    )
                    gap_fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), showlegend=False, xaxis_title="Gap size", yaxis_title="Frequency")
                    st.plotly_chart(gap_fig, use_container_width=True)

                render_zwc_sequence_view(text, input_source_label)

            with st.expander("Raw statistics report", expanded=True):
                output, _ = capture_print_output(attack_stats, text)
                st.code(output, language="text")

elif action_key == "Raw Extract":
    if run_pressed:
        st.markdown("### Raw Bit Extraction")
        st.caption("Inspect the baseline bit stream and the decoded message output.")

        raw_zwc_count = sum(1 for ch in text if ch in ("\u200B", "\u200C"))
        raw_bits = raw_zwc_count
        estimated_bytes = raw_bits // 8

        raw_left, raw_mid, raw_right = st.columns([1, 1, 1])
        raw_left.metric("Detected ZWC chars", raw_zwc_count)
        raw_mid.metric("Extractable bits", raw_bits)
        raw_right.metric("Estimated bytes", f"~{estimated_bytes}")

        with st.container():
            preview_col, report_col = st.columns([1.4, 1])
            with preview_col:
                st.markdown("#### Quick Preview")
                extracted_bits = "".join("0" if ch == "\u200B" else "1" for ch in text if ch in ("\u200B", "\u200C"))
                if extracted_bits:
                    st.code(f"First 96 bits:\n{extracted_bits[:96]}", language="text")
                else:
                    st.info("No baseline zero-width characters found to extract.")
            with report_col:
                st.markdown("#### Output Summary")
                st.write("The raw report shows the decoded payload and any extraction notes.")

            with st.expander("Raw extraction report", expanded=True):
                output, _ = capture_print_output(attack_extract_raw, text)
                st.code(output, language="text")

elif action_key == "Decode with Known Passkey":
    st.markdown("### Passkey Decode")
    st.caption("Attempt enhanced payload recovery with a known passkey.")

    decode_left, decode_right = st.columns([1.6, 1])
    with decode_left:
        passkey = st.text_input("Passkey", type="password")
        st.caption("Enter the passkey, then use the main Run button above.")
    with decode_right:
        decode_total_chars, decode_visible_chars, decode_zwc_total, _ = zwc_summary(text)
        st.metric("Total characters", decode_total_chars)
        st.metric("Visible characters", decode_visible_chars)
        st.metric("ZWC characters", decode_zwc_total)

    if run_pressed:
        if not passkey:
            st.error("Please enter a passkey.")
        else:
            with st.spinner("Decoding enhanced payload with known passkey..."):
                result = decode_enhanced_with_key(text, passkey)

            if result.startswith("[FAIL]") or result.startswith("[ERROR]"):
                st.error(result)
                st.info("If this is an enhanced stego file, check that the passkey exactly matches the one used during embedding and that the text has not been stripped, substituted, or corrupted.")
            else:
                st.success("Message decoded successfully.")
                with st.expander("Decoded message", expanded=True):
                    st.code(result, language="text")

elif action_key == "Strip Attack":
    st.markdown("### Strip Attack")
    st.caption("Remove every known zero-width character and export the cleaned text.")
    if run_pressed:
        strip_setup_left, strip_metrics_right = st.columns([1, 1.2])
        with strip_setup_left:
            st.caption("Attack Setup")
            st.caption("Mode: Strip all known ZWC characters")
            st.caption("Output file: clean.txt")

        with st.spinner("Running strip attack..."):
            output, clean_text = capture_print_output(attack_strip, text)

        with strip_metrics_right:
            render_attack_metrics(text, clean_text)

        render_active_attack_status(output, "Strip attack")

        st.markdown("#### Cleaned Output")
        st.download_button("Download clean.txt", clean_text.encode("utf-8"), file_name="clean.txt", mime="text/plain")

        with st.expander("Strip report", expanded=True):
            st.code(output, language="text")

elif action_key == "Noise Attack":
    st.markdown("### Noise Attack")
    st.caption("Inject random zero-width noise after spaces and export the corrupted text.")
    density = st.slider("Noise density", 0.0, 1.0, 0.3, 0.05)
    if run_pressed:
        noise_setup_left, noise_metrics_right = st.columns([1, 1.2])
        with noise_setup_left:
            st.caption("Attack Setup")
            st.caption(f"Mode: Inject ZWC noise | Density: {density:.2f}")
            st.caption("Output file: noisy.txt")

        with st.spinner("Running noise attack..."):
            output, noisy_text = capture_print_output(attack_noise, text, density)

        with noise_metrics_right:
            render_attack_metrics(text, noisy_text)

        render_active_attack_status(output, "Noise attack")

        st.markdown("#### Noisy Output")
        st.download_button("Download noisy.txt", noisy_text.encode("utf-8"), file_name="noisy.txt", mime="text/plain")

        with st.expander("Noise report", expanded=True):
            st.code(output, language="text")

elif action_key == "Substitution Attack":
    st.markdown("### Substitution Attack")
    st.caption("Replace baseline zero-width symbols with a different invisible symbol.")
    if run_pressed:
        sub_setup_left, sub_metrics_right = st.columns([1, 1.2])
        with sub_setup_left:
            st.caption("Attack Setup")
            st.caption("Mode: Substitute U+200B/U+200C with U+2060")
            st.caption("Output file: substituted.txt")

        with st.spinner("Running substitution attack..."):
            output, substituted_text = capture_print_output(attack_substitute, text)

        with sub_metrics_right:
            render_attack_metrics(text, substituted_text)

        render_active_attack_status(output, "Substitution attack")

        st.markdown("#### Substituted Output")
        st.download_button("Download substituted.txt", substituted_text.encode("utf-8"), file_name="substituted.txt", mime="text/plain")

        with st.expander("Substitution report", expanded=True):
            st.code(output, language="text")

elif action_key == "Brute Force":
    st.markdown("### Brute Force")
    st.caption("Try candidate passkeys using pasted text, an uploaded file, or the built-in list.")
    brute_mode = st.radio(
        "Candidate input method",
        ["Paste passkeys", "Upload .txt passkeys", "Use built-in test list"],
        horizontal=True,
    )

    pasted_passkeys = ""
    wordlist_file = None
    if brute_mode == "Paste passkeys":
        pasted_passkeys = st.text_area(
            "Enter passkeys (one per line)",
            height=180,
            placeholder="password\nsecret\nMyKey123!",
        )
        st.caption("Each non-empty line is treated as one candidate. Lines starting with # are ignored.")
    elif brute_mode == "Upload .txt passkeys":
        wordlist_file = st.file_uploader("Upload passkeys .txt file", type=["txt"], key="passkeys_wordlist")
        st.caption("Upload a plain text file with one passkey per line.")
    else:
        st.info("The built-in candidate list will be used.")

    if run_pressed:
        brute_setup_left, brute_metrics_right = st.columns([1, 1.2])
        with brute_setup_left:
            st.caption("Candidate Setup")
            if brute_mode == "Paste passkeys":
                st.caption(f"Mode: Paste passkeys | Candidates: {len(parse_passkey_candidates(pasted_passkeys))}")
            elif brute_mode == "Upload .txt passkeys":
                st.caption("Mode: Upload .txt passkeys | Uploaded wordlist file: ready")
            else:
                st.caption("Mode: Built-in test list | Using built-in test list")

        with brute_metrics_right:
            brute_total_chars, brute_visible_chars, brute_zwc_total, _ = zwc_summary(text)
            brute_metric_1, brute_metric_2, brute_metric_3 = st.columns(3)
            with brute_metric_1:
                st.metric("Total characters", brute_total_chars)
            with brute_metric_2:
                st.metric("Visible characters", brute_visible_chars)
            with brute_metric_3:
                st.metric("ZWC characters", brute_zwc_total)

        if brute_mode == "Paste passkeys":
            candidates = parse_passkey_candidates(pasted_passkeys)
            with st.spinner("Running brute-force against pasted candidates..."):
                output, _ = capture_print_output(attack_brute_candidates, text, candidates)
            render_brute_status(output)
            with st.expander("Brute force report", expanded=True):
                st.code(output, language="text")
        elif brute_mode == "Upload .txt passkeys" and wordlist_file is not None:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="wb") as tmp:
                tmp.write(wordlist_file.getvalue())
                wordlist_path = tmp.name

            with st.spinner("Running brute-force against uploaded wordlist..."):
                output, _ = capture_print_output(attack_brute, text, wordlist_path)
            render_brute_status(output)
            with st.expander("Brute force report", expanded=True):
                st.code(output, language="text")

            if os.path.exists(wordlist_path):
                os.remove(wordlist_path)
        else:
            with st.spinner("Running brute-force with built-in candidates..."):
                output, _ = capture_print_output(attack_brute, text, "wordlist.txt")
            render_brute_status(output)
            with st.expander("Brute force report", expanded=True):
                st.code(output, language="text")

elif action_key == "Full Passive Scan":
    st.markdown("### Full Passive Scan")
    st.caption("Run scan, statistics, and raw extraction together.")
    if run_pressed:
        with st.spinner("Running full passive scan..."):
            output1, present = capture_print_output(attack_scan, text)
            output2, _ = capture_print_output(attack_stats, text) if present else ("", None)
            output3, _ = capture_print_output(attack_extract_raw, text) if present else ("", None)

        total_chars, visible_chars, zwc_total, ratio = zwc_summary(text)
        full_freq_df = zwc_frequency_table(text)
        positions, gaps, avg_gap = zwc_position_stats(text)
        distinct_types = len(full_freq_df)
        estimated_bits = zwc_total * 2 if distinct_types == 4 else zwc_total if distinct_types == 2 else 0
        estimated_bytes = estimated_bits // 8 if estimated_bits else 0

        if present:
            st.success("Zero-width characters detected. Passive scan completed.")
        else:
            st.warning("No known zero-width characters detected. Statistics and extraction were skipped.")

        st.markdown("#### Scan Dashboard")
        full_metric_1, full_metric_2, full_metric_3, full_metric_4 = st.columns(4)
        with full_metric_1:
            st.metric("Total characters", total_chars)
        with full_metric_2:
            st.metric("Visible characters", visible_chars)
        with full_metric_3:
            st.metric("ZWC characters", zwc_total)
        with full_metric_4:
            st.metric("Estimated payload", f"~{estimated_bytes} bytes")

        if not full_freq_df.empty:
            st.markdown("#### Visual Summary")
            chart_col, table_col = st.columns([1.7, 1])
            with chart_col:
                if PLOTLY_AVAILABLE:
                    full_fig = px.bar(
                        full_freq_df,
                        x="Unicode",
                        y="Count",
                        color="Name",
                        text="Count",
                        height=300,
                    )
                    full_fig.update_layout(
                        margin=dict(l=0, r=0, t=20, b=0),
                        showlegend=False,
                        xaxis_title="Unicode Character",
                        yaxis_title="Count",
                    )
                    st.plotly_chart(full_fig, use_container_width=True)
                else:
                    st.bar_chart(full_freq_df.set_index("Unicode")["Count"])

            with table_col:
                st.markdown("#### Detected Types")
                st.dataframe(full_freq_df, use_container_width=True, height=220)

            st.markdown("#### Position & Extraction Summary")
            position_col, extract_col = st.columns([1, 1.4])
            with position_col:
                st.metric("Distinct ZWC types", distinct_types)
                st.metric("First ZWC position", positions[0] if positions else "N/A")
                st.metric("Average gap", f"{avg_gap:.1f}" if gaps else "N/A")

            with extract_col:
                extracted_bits = "".join("0" if ch == "\u200B" else "1" for ch in text if ch in ("\u200B", "\u200C"))
                if extracted_bits:
                    st.code(f"First 96 baseline bits:\n{extracted_bits[:96]}", language="text")
                else:
                    st.info("No U+200B/U+200C baseline bits found for raw extraction preview.")

            if gaps:
                st.markdown("#### Gap Distribution")
                if PLOTLY_AVAILABLE:
                    full_gap_fig = px.histogram(
                        x=gaps,
                        nbins=min(20, max(5, len(gaps) // 10)),
                        labels={"x": "Gap size"},
                        height=240,
                    )
                    full_gap_fig.update_layout(
                        margin=dict(l=0, r=0, t=10, b=0),
                        showlegend=False,
                        xaxis_title="Gap size",
                        yaxis_title="Frequency",
                    )
                    st.plotly_chart(full_gap_fig, use_container_width=True)
                else:
                    st.bar_chart(pd.Series(gaps).value_counts().sort_index())

            render_zwc_sequence_view(text, input_source_label)

        with st.expander("Full passive scan report", expanded=True):
            st.markdown("##### Scanner")
            st.code(output1, language="text")
            if present:
                st.markdown("##### Statistics")
                st.code(output2, language="text")
                st.markdown("##### Raw Extraction")
                st.code(output3, language="text")
