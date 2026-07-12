# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Isaac Teague Frayling
"""Neutralise prompt-injection / tool-poisoning in untrusted tool text before it reaches an LLM's system prompt.

When an agent consumes tools from an external / third-party source (e.g. an MCP server), that server's tool
NAME and DESCRIPTION are attacker-controlled text — and they get rendered into the *trusted* instruction
channel (the planner's system prompt) so the model knows what tools exist. A hostile server can exploit that:

  * fake a tool-call — embed `<function_calls>…` / a `{"action": ...}` object in a description so the model
    thinks a tool was invoked;
  * hide or reorder text — Unicode zero-width and bidirectional-override characters that render invisibly, so
    the human review sees one thing and the model sees another;
  * smuggle instructions across lines — a multi-line description that reads as new system directives.

`sanitize_remote_tool_text` collapses all of that to inert, single-line prose: it strips invisible/bidi/control
characters, removes tool-protocol markup, flattens whitespace so nothing can span or inject instructions, and
caps the length. Run it on every untrusted tool name and description before they touch the prompt.

Extracted from PANTHEON (a multi-tenant AI substrate), where it guards the inbound MCP transport — the point
where a governed agent consumes an external, possibly-hostile server's tools.

    from tool_sanitizer import sanitize_remote_tool_text
    safe_name = sanitize_remote_tool_text(remote_tool["name"], max_len=64)
    safe_desc = sanitize_remote_tool_text(remote_tool["description"])
    if not safe_name:        # a name that sanitises to nothing (pure markup/invisibles) is unsafe → skip the tool
        continue
"""
from __future__ import annotations

import re

# a model (or an injected description) reverting to native tool-use syntax — XML like
# <function_calls>/<invoke>/<parameter>/<antml…>, or the start of a `[{` array or `{"` object.
TOOL_MARK_RE = re.compile(r'\{\s*"|\[\s*\{|<\s*/?\s*(?:function_calls?|invoke|parameter|antml)', re.I)

# control chars + the Unicode zero-width / bidirectional-override run that hides or reorders text invisibly
# (a classic prompt-injection smuggle): U+200B–200F, U+202A–202E (bidi embeddings/overrides),
# U+2066–2069 (isolates), U+FEFF (BOM / zero-width no-break space).
_INVISIBLE_RE = re.compile("[\x00-\x1f\x7f​-‏‪-‮⁦-⁩﻿]")


def strip_tool_markup(text: str) -> str:
    """Strip any tool-protocol residue mixed into text — function-call XML and a `{"action": ...}` object — so
    it can't be mistaken for a real tool invocation. Useful on model OUTPUT too (so a user never sees markup).

    Iterated to a fixpoint: a single removal pass is bypassable, because deleting an *inner* match can rejoin
    the surrounding fragments into a fresh one (`<in<invoke>voke>` -> `<invoke>`; `{"act{"action":..}ion":..}`
    -> `{"action":..}`). We re-run until a pass changes nothing — guaranteed to terminate, since every pass
    only ever removes characters (length strictly decreases until stable)."""
    prev = None
    while prev != text:
        prev = text
        text = re.sub(r'<\s*/?\s*(?:function_calls?|invoke|parameter|antml)\b[^>]*>', '', text, flags=re.I)
        text = re.sub(r'\{\s*"action"\s*:.*?\}', '', text, flags=re.S)
    return text.strip()


def sanitize_remote_tool_text(text: str, *, max_len: int = 300) -> str:
    """Neutralise an untrusted tool's name/description before it reaches an LLM system prompt. Strips
    invisible/bidi/control characters, removes tool-protocol markup (so it can't fake a tool call), collapses
    all whitespace to single spaces (no multi-line instruction smuggling), and caps length. Returns inert prose
    — or the empty string if nothing safe remains (a signal the tool should be skipped)."""
    if not text:
        return ""
    text = _INVISIBLE_RE.sub("", str(text))
    text = strip_tool_markup(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_len].strip()          # strip AFTER the cut too — truncation can land on a space
