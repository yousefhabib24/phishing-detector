"""
app.py

Streamlit UI for the phishing email checker. Wraps core.check_email()
so a non-technical person can paste an email and get a clear, plain-
English verdict -- no technical knowledge required.

Run with: streamlit run app.py
"""

import re

import streamlit as st

from core import check_email, check_email_file
from llm_analysis import Verdict


st.set_page_config(
    page_title="Is This Phishing?",
    page_icon="🎣",
    layout="centered",
)

# ---------------------------------------------------------------------------
# Design tokens
# ---------------------------------------------------------------------------
TOKENS = {
    "bg": "#F7F9FB",
    "text": "#1B2430",
    "text_muted": "#5B6472",
    "accent": "#3454D1",
    "card_bg": "#FFFFFF",
    "border": "#E3E8EF",
    "font_display": "'Space Grotesk', sans-serif",
    "font_body": "'Inter', sans-serif",
    "font_mono": "'IBM Plex Mono', monospace",
}

RISK_STYLES = {
    "safe": {"color": "#1F9D55", "bg": "#E9F9EF", "label": "Looks Safe", "icon": "✅"},
    "suspicious": {"color": "#B7791F", "bg": "#FFF6E0", "label": "Suspicious", "icon": "⚠️"},
    "dangerous": {"color": "#C53030", "bg": "#FDEDED", "label": "Dangerous", "icon": "🚨"},
}

# Simple abuse guardrail: caps how many checks one browser session can run.
MAX_CHECKS_PER_SESSION = 3


def inject_custom_css() -> None:
    """Loads our fonts and overrides Streamlit's default styling with our
    own design tokens. This runs once at the top of the page."""
    st.markdown(
        f"""
        <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=Inter:wght@400;500;600&family=IBM+Plex+Mono:wght@500&display=swap" rel="stylesheet">
        <style>
            .stApp {{
                background-color: {TOKENS['bg']};
                font-family: {TOKENS['font_body']};
                color: {TOKENS['text']};
            }}

            h1, h2, h3 {{
                font-family: {TOKENS['font_display']} !important;
                color: {TOKENS['text']} !important;
            }}

            h1 {{
                letter-spacing: -0.5px;
            }}

            .stTextArea textarea {{
                border-radius: 10px !important;
                border: 1px solid {TOKENS['border']} !important;
                font-family: {TOKENS['font_body']} !important;
                background-color: {TOKENS['card_bg']} !important;
            }}
            .stTextArea textarea:focus {{
                border-color: {TOKENS['accent']} !important;
                box-shadow: 0 0 0 1px {TOKENS['accent']} !important;
            }}

            .stButton button[kind="primary"] {{
                background-color: {TOKENS['accent']} !important;
                border-color: {TOKENS['accent']} !important;
                border-radius: 8px !important;
                font-family: {TOKENS['font_display']} !important;
                font-weight: 700 !important;
                letter-spacing: 0.2px;
            }}
            .stButton button[kind="primary"]:hover {{
                background-color: #2A44B0 !important;
                border-color: #2A44B0 !important;
            }}

            .evidence-chip {{
                font-family: {TOKENS['font_mono']};
                font-size: 12.5px;
                background-color: #F0F2F6;
                border: 1px solid {TOKENS['border']};
                border-radius: 5px;
                padding: 2px 7px;
                display: inline-block;
                color: {TOKENS['text']};
            }}
        </style>
        """,
        unsafe_allow_html=True,
    )


# Matches things that look like a domain or URL inside a sentence, e.g.
# "paypa1-secure.com" or "http://192.168.1.5/verify" -- used to visually
# tag raw evidence inside the AI's plain-English explanations.
_EVIDENCE_PATTERN = re.compile(
    r"(https?://[^\s<>\"')]+|\b[\w-]+(?:\.[\w-]+)+\.[a-z]{2,}\b)",
    re.IGNORECASE,
)


def highlight_evidence(text: str) -> str:
    """Wraps any domain/URL-looking substrings in a monospace 'chip' span,
    so raw technical evidence visually stands apart from plain-English
    explanation -- reinforcing that these are facts, not opinions."""
    return _EVIDENCE_PATTERN.sub(
        lambda m: f'<span class="evidence-chip">{m.group(0)}</span>', text
    )


def render_verdict(verdict: Verdict) -> None:
    style = RISK_STYLES.get(verdict.risk_level, RISK_STYLES["suspicious"])

    if verdict.is_mock:
        st.info(
            "🔧 Running in **mock mode** — no live AI analysis yet. "
            "This is placeholder output based only on rule-based checks.",
            icon="🔧",
        )

    # dir="auto" lets the browser detect each block's actual text direction
    # (left-to-right vs right-to-left) from its content, instead of
    # assuming left-to-right by default -- without this, Arabic text renders
    # with punctuation in the wrong visual position, since the browser lays
    # it out according to the container's assumed direction, not the text's.
    st.markdown(
        f"""
        <div dir="auto" style="
            background-color:{style['bg']};
            border:1px solid {style['color']};
            border-radius:12px;
            padding:22px 24px;
            margin-bottom:24px;
        ">
            <div style="font-family:{TOKENS['font_display']}; font-size:23px; font-weight:700; color:{style['color']};">
                {style['icon']} {style['label']}
            </div>
            <div dir="auto" style="margin-top:10px; font-size:15px; line-height:1.5; color:{TOKENS['text']};">
                {highlight_evidence(verdict.summary)}
            </div>
            <div style="margin-top:10px; font-size:12.5px; font-family:{TOKENS['font_mono']}; color:{TOKENS['text_muted']}; text-transform:uppercase; letter-spacing:0.5px;">
                Confidence: {verdict.confidence}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if verdict.red_flags:
        st.markdown(
            f"<h3 style='font-family:{TOKENS['font_display']};'>What we found</h3>",
            unsafe_allow_html=True,
        )
        for flag in verdict.red_flags:
            st.markdown(
                f"""
                <div dir="auto" style="
                    background-color:{TOKENS['card_bg']};
                    border:1px solid {TOKENS['border']};
                    border-radius:10px;
                    padding:16px 18px;
                    margin-bottom:12px;
                ">
                    <div dir="auto" style="font-family:{TOKENS['font_display']}; font-weight:700; font-size:15px; margin-bottom:6px;">
                        {flag.title}
                    </div>
                    <div dir="auto" style="font-size:14px; line-height:1.5; color:{TOKENS['text_muted']};">
                        {highlight_evidence(flag.explanation)}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.markdown("No specific red flags were identified.")

    if verdict.reassurance_notes:
        st.markdown("---")
        st.markdown(
            f"<div dir='auto' style='font-style:italic; color:{TOKENS['text_muted']};'>{verdict.reassurance_notes}</div>",
            unsafe_allow_html=True,
        )


def main() -> None:
    inject_custom_css()

    st.title("🎣 Is This Phishing?")
    st.markdown(
        f"<div style='color:{TOKENS['text_muted']}; font-size:16px; margin-top:-8px;'>"
        "Paste an email you're unsure about below. We'll check it for "
        "common phishing red flags and give you a plain-English verdict — "
        "free, no sign-up required."
        "</div>",
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
        <div style="
            background-color:#EEF1FB;
            border:1px solid {TOKENS['accent']};
            border-left:4px solid {TOKENS['accent']};
            border-radius:8px;
            padding:14px 18px;
            margin:18px 0;
            font-size:13.5px;
            line-height:1.5;
            color:{TOKENS['text']};
        ">
            <strong>🔒 Before you paste anything:</strong> don't include real passwords,
            verification codes, or other highly sensitive personal data. This is an early,
            independent project — great for checking suspicious emails, not for storing
            confidential information.
        </div>
        """,
        unsafe_allow_html=True,
    )

    if "check_count" not in st.session_state:
        st.session_state.check_count = 0
    if "last_result" not in st.session_state:
        st.session_state.last_result = None

    checks_remaining = MAX_CHECKS_PER_SESSION - st.session_state.check_count
    limit_reached = checks_remaining <= 0

    st.caption(f"{max(checks_remaining, 0)} of {MAX_CHECKS_PER_SESSION} checks remaining this session.")

    def process_check(run_check) -> None:
        st.session_state.check_count += 1
        with st.spinner("Analyzing..."):
            try:
                verdict = run_check()
            except Exception as e:  # noqa: BLE001
                st.session_state.last_result = ("error", str(e))
            else:
                st.session_state.last_result = ("verdict", verdict)
        st.rerun()

    paste_tab, upload_tab = st.tabs(["📋 Paste Text", "📎 Upload .eml File"])

    with paste_tab:
        email_text = st.text_area(
            "Paste the email text here (subject + body, and the sender's name/address if you have it):",
            height=260,
            placeholder=(
                "From: PayPal Support <support@example.com>\n"
                "Subject: Your account will be suspended\n\n"
                "Dear Customer, we noticed unusual activity..."
            ),
            disabled=limit_reached,
        )
        paste_clicked = st.button(
            "Check This Email",
            type="primary",
            use_container_width=True,
            disabled=limit_reached,
            key="paste_check_button",
        )

    with upload_tab:
        st.caption(
            "Uploading the real .eml file (instead of pasting text) unlocks stronger "
            "checks -- real SPF/DKIM/DMARC authentication results, which can catch a "
            "perfectly spoofed sender address that text alone never could. In most "
            "email apps, look for 'Show Original', 'Download message', or 'Save as...' "
            "to get this file."
        )
        uploaded_file = st.file_uploader(
            "Upload the raw .eml file",
            type=["eml"],
            disabled=limit_reached,
        )
        upload_clicked = st.button(
            "Check This Email",
            type="primary",
            use_container_width=True,
            disabled=limit_reached,
            key="upload_check_button",
        )

    if limit_reached:
        st.warning("You've used all your checks for this session. Refresh the page to reset.")

    if paste_clicked and not limit_reached:
        if not email_text.strip():
            st.warning("Paste an email above before checking.")
        else:
            process_check(lambda: check_email(email_text))

    if upload_clicked and not limit_reached:
        if uploaded_file is None:
            st.warning("Upload a .eml file above before checking.")
        else:
            process_check(lambda: check_email_file(uploaded_file.getvalue()))

    if st.session_state.last_result is not None:
        kind, payload = st.session_state.last_result
        if kind == "verdict":
            render_verdict(payload)
        else:
            st.error(f"Something went wrong while analyzing this email: {payload}")

    st.markdown("---")
    st.caption(
        "This tool provides guidance, not certainty. When in doubt, don't click links or "
        "share information — contact the organization directly using a phone number or "
        "website you already trust, not one from the email itself."
    )


if __name__ == "__main__":
    main()
