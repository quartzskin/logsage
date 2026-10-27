# logsage

Reads Windows event log exports and Linux auth.log files, groups related events, and writes a report that keeps four things apart: raw facts (with event ids or line numbers), interpretation, confidence, and unknowns. Interpretation can come from a local Ollama model or from a small built-in rule set. No dependencies, Node 24+ (developed on 26).

## Usage

    node bin/logsage.js serve                  # web UI on http://127.0.0.1:8787
    node bin/logsage.js report samples/auth.log --year 2024 --out report.md

Add `--model llama3.1` (or set `LOGSAGE_MODEL`) to use Ollama at `http://127.0.0.1:11434`; `--ollama URL` or `LOGSAGE_OLLAMA_URL` changes the address. Without a model, or if the model call fails, the rule-based reading is used and the report says so.

Inputs, detected from the first character: wevtutil XML (`wevtutil qe Security /f:xml`), JSON lines from `Get-WinEvent | ConvertTo-Json -Compress` (one object per line), and syslog-style auth.log. Samples are in `samples/` and are made up.

What gets grouped: bursts of failed logons (3+ from one source within 10 minutes) and whether a success and a 4672 follow, 4672/sudo use, service installs (7045/4697), account creation, group changes, and log clearing (1102).

The web UI keeps reports in a local SQLite file (`logsage.db`), can export Markdown, and has a question box. The question box picks matching stored events by keyword; with a model it is asked to answer from those events only, otherwise the matching events are listed.

## Redaction

Before any model call, usernames, IPs, hostnames, domains, emails and SIDs are replaced with aliases (`USER_1`, `IP_1`, ...) and swapped back locally in the reply. The model only gets group facts and the redacted events they cite. Model replies are kept only if they cite evidence refs that exist; the rest is dropped and noted under unknowns. The endpoint must be a loopback address unless the client is built with `allowRemote`.

Log text is passed to the model as JSON data under a system prompt that says it is untrusted, and model output is never executed or used to pick tools. This lowers the risk from injected text in logs; it does not remove it, since a model can still be swayed in its wording. The tests cover the tool side (grouping, refs, prompt layout), not model behaviour.

## Tests

    node --test

The Ollama tests run against a fake HTTP server. They have not been run against a real Ollama, so the prompts and the JSON shape it returns are untested with a real model.

## Limits

- Only the event ids listed above are understood; everything else is parsed but ungrouped.
- Redaction is pattern and known-value based. Names that only appear in free text of events with no user field can slip through.
- Message parsing for JSON-lines assumes English event text.
- auth.log has no year; pass `--year` on the CLI (the UI uses the current year).
- Timestamps are treated as UTC.
