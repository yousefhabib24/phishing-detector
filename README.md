# PhishyMax 🎣

A free tool that checks whether an email you received looks like phishing —
paste the email, get a plain-Language verdict, no technical knowledge or
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