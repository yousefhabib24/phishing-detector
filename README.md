# Is This Phishing? 🎣

A free tool that checks whether an email you received looks like phishing —
paste the email, get a plain-English verdict, no technical knowledge or
sign-up required.

## Why this exists

Phishing emails are getting harder to spot, especially as attackers use AI
to write more convincing messages. Most existing tools are built for IT
teams, not for the average person who just got a weird email and wants a
quick, trustworthy answer.

## How it works

This tool combines two layers:

1. **Rule-based checks** — looks for objective red flags: sender addresses
   that don't match the brand they claim to be, suspicious links (raw IP
   addresses, URL shorteners, lookalike domains), urgency language, and
   requests for sensitive information.
2. **AI reasoning (Claude)** — takes those technical findings plus the
   actual email content and reasons about whether the whole thing adds up,
   the same way a security-aware person would read it. This catches things
   pure rules miss, like social-engineering pretexts with no bad links at all.

The two layers together aim to be both **explainable** (you can see exactly
why something was flagged) and **adaptable** (not just matching a fixed list
of known scam patterns).

## Current limitations (v1)

- Only checks **pasted visible text** (subject/body/sender line), not raw
  email headers — so it can't yet verify SPF/DKIM/DMARC authentication.
  Raw-header support is planned for a future version.
- English-language emails work best.
- This is guidance, not a guarantee. When in doubt about a real email,
  always contact the organization directly using contact info you already
  trust — not anything from the email itself.

## Running it locally

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. (Optional, for real AI analysis instead of mock mode) Set your Anthropic
   API key as an environment variable:
   ```
   set ANTHROPIC_API_KEY=your-key-here      # Windows (cmd)
   $env:ANTHROPIC_API_KEY="your-key-here"   # Windows (PowerShell)
   ```
   Without a key set, the app runs in **mock mode** — it still works and
   shows results, but based only on the rule-based checks, clearly labeled
   as mock output.

3. Run the app:
   ```
   streamlit run app.py
   ```

4. It'll open in your browser automatically (usually at
   http://localhost:8501).

## Project structure

```
phishing-detector/
├── app.py              # Streamlit UI
├── core.py             # Ties heuristics + LLM analysis together
├── heuristics.py        # Rule-based detection layer
├── llm_analysis.py      # Claude-powered reasoning layer
├── requirements.txt
└── tests/
    └── sample_emails.py  # Manual test cases for the heuristics engine
```

## Roadmap

- [ ] Raw email header support (unlocks SPF/DKIM/DMARC verification)
- [ ] Browser extension (check emails directly in Gmail/Outlook)
- [ ] Support for languages beyond English
