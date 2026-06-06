import io
import os
import sys
import tempfile
from contextlib import redirect_stdout

import pandas as pd
import streamlit as st
try:
    import plotly.express as px
    PLOTLY_AVAILABLE = True
except Exception:
    px = None
    PLOTLY_AVAILABLE = False

# Import functions from your separate toolkit file
from zwc_attack_toolkit_old import (
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
    page_title="ZWC Steganography Attack Toolkit",
    page_icon="🕵️",
    layout="wide",
)

# --- Small visual improvements via CSS ---
st.markdown(
    """
    <style>
    .stApp { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial; }
    .title { display:flex; align-items:center; gap:12px }
    .metric-label { color: #6b7280; font-size:0.9rem }
    .card { background: #ffffff; padding: 12px; border-radius: 10px; box-shadow: 0 1px 3px rgba(16,24,40,0.05); }
    .small-muted { color:#6b7280; font-size:0.85rem }
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


st.markdown('<div class="title"><h1>🕵️ ZWC Steganography Attack Toolkit</h1></div>', unsafe_allow_html=True)
st.caption("Streamlined UI for scanning, analyzing, decoding, and attacking zero-width-character stego text.")

with st.sidebar:
    st.subheader("Input & Options")
    uploaded_file = st.file_uploader("Upload stego text file", type=["txt", "text", "csv", "md"])
    manual_text = st.text_area("Or paste text here", height=180, placeholder="Paste stego text here...")
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

file_text = read_uploaded_text(uploaded_file)
text = manual_text if manual_text.strip() else file_text

if not text:
    st.info("Upload a text file or paste text in the sidebar to begin.")
    st.stop()

col1, col2, col3, col4 = st.columns([1.5, 1, 1, 1])
total_chars, visible_chars, zwc_total, ratio = zwc_summary(text)
col1.metric("Total characters", total_chars, help="Total length including invisible characters")
col2.metric("Visible characters", visible_chars)
col3.metric("ZWC characters", zwc_total)
col4.metric("ZWC / visible ratio", f"{ratio:.4f}")

freq_df = zwc_frequency_table(text)
if not freq_df.empty:
    with st.container():
        st.subheader("Detected ZWC characters")
        left, right = st.columns([1, 2])
        left.dataframe(freq_df, use_container_width=True, height=160)
        # simple bar plot
        if PLOTLY_AVAILABLE:
            fig = px.bar(freq_df, x="Unicode", y="Count", text="Count", height=180)
            fig.update_layout(margin=dict(l=0, r=0, t=10, b=10))
            right.plotly_chart(fig, use_container_width=True)
        else:
            # Fallback to Streamlit's builtin chart if plotly isn't installed
            right.write("Plotly not installed — showing simple bar chart fallback.")
            series = freq_df.set_index('Unicode')['Count']
            right.bar_chart(series)
else:
    st.warning("No known zero-width characters detected.")

st.divider()

# Normalize selected action key (strip emoji)
action_key = action.split(' ', 1)[1] if ' ' in action else action

# Prominent action header and run button
st.markdown(f"### {action}")
st.caption(ACTION_DESCRIPTIONS.get(action, ""))

run_col1, run_col2, run_col3 = st.columns([1, 2, 1])
with run_col2:
    if st.button(f"Run {action}", key="run_action"):
        run_pressed = True
    else:
        run_pressed = False

st.write('')

if action_key == "Scan":
    st.subheader("Passive Attack 1 — ZWC Scanner")
    if run_pressed:
        output, _ = capture_print_output(attack_scan, text)
        with st.expander("Scanner output", expanded=True):
            st.code(output, language="text")

elif action_key == "Statistics":
    st.subheader("Passive Attack 2 — Statistical Analysis")
    if run_pressed:
        with st.expander("Statistics", expanded=True):
            output, _ = capture_print_output(attack_stats, text)
            st.code(output, language="text")

elif action_key == "Raw Extract":
    st.subheader("Passive Attack 3 — Raw Bit Extraction")
    if run_pressed:
        with st.expander("Extracted bits and decoded text (if any)", expanded=True):
            output, _ = capture_print_output(attack_extract_raw, text)
            st.code(output, language="text")

elif action_key == "Decode with Known Passkey":
    st.subheader("Passive Attack 4 — Decode Enhanced Version with Known Passkey")
    passkey = st.text_input("Passkey", type="password")
    if st.button("Decode now"):
        if not passkey:
            st.error("Please enter a passkey.")
        else:
            result = decode_enhanced_with_key(text, passkey)
            if result.startswith("[FAIL]") or result.startswith("[ERROR]"):
                st.error(result)
            else:
                st.success("Message decoded successfully.")
                st.code(result, language="text")

elif action_key == "Strip Attack":
    st.subheader("Active Attack 5 — Strip All ZWC Characters")
    if run_pressed:
        output, clean_text = capture_print_output(attack_strip, text)
        with st.expander("Output", expanded=True):
            st.code(output, language="text")
        st.download_button("Download clean.txt", clean_text.encode("utf-8"), file_name="clean.txt", mime="text/plain")

elif action_key == "Noise Attack":
    st.subheader("Active Attack 6 — Inject Random ZWC Noise")
    density = st.slider("Noise density", 0.0, 1.0, 0.3, 0.05)
    if run_pressed:
        output, noisy_text = capture_print_output(attack_noise, text, density)
        with st.expander("Output", expanded=True):
            st.code(output, language="text")
        st.download_button("Download noisy.txt", noisy_text.encode("utf-8"), file_name="noisy.txt", mime="text/plain")

elif action_key == "Substitution Attack":
    st.subheader("Active Attack 7 — Substitute Original ZWC Symbols")
    if run_pressed:
        output, substituted_text = capture_print_output(attack_substitute, text)
        with st.expander("Output", expanded=True):
            st.code(output, language="text")
        st.download_button("Download substituted.txt", substituted_text.encode("utf-8"), file_name="substituted.txt", mime="text/plain")

elif action_key == "Brute Force":
    st.subheader("Active Attack 8/9 — Passkey Brute Force")
    wordlist_file = st.file_uploader("Upload wordlist file", type=["txt"], key="wordlist")
    wordlist_hint = st.empty()
    if wordlist_file is None:
        wordlist_hint.info("No wordlist uploaded — built-in test list will be used.")

    if run_pressed:
        if wordlist_file is not None:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="wb") as tmp:
                tmp.write(wordlist_file.getvalue())
                wordlist_path = tmp.name
        else:
            wordlist_path = "wordlist.txt"

        with st.spinner("Running brute-force (this may take time)..."):
            output, _ = capture_print_output(attack_brute, text, wordlist_path)
        st.code(output, language="text")

        if wordlist_file is not None and os.path.exists(wordlist_path):
            os.remove(wordlist_path)

elif action_key == "Full Passive Scan":
    st.subheader("Comprehensive Full Passive Scan")
    if run_pressed:
        with st.expander("Run full passive scan (scan → stats → raw extract)", expanded=True):
            output1, present = capture_print_output(attack_scan, text)
            st.code(output1, language="text")
            if present:
                output2, _ = capture_print_output(attack_stats, text)
                output3, _ = capture_print_output(attack_extract_raw, text)
                st.code(output2, language="text")
                st.code(output3, language="text")
