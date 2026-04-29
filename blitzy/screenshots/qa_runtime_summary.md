# QA Checkpoint 13 — Runtime Re-Verification Summary

This file summarises the runtime re-verification evidence captured for
QA findings #1 and #2 of the **Final Checkpoint 13** test report.

## Issue #1 — sshtalk Arc::get_mut antipattern

**Evidence file**: `issue1_sshtalk_runtime_31833bytes.bin` (31,833 bytes)

**Pre-fix baseline**: 142 bytes total (35 widget bytes post-handshake)
**Post-fix capture**: 31,833 bytes total (31,717 widget bytes post-handshake)
**Improvement**: **906× increase in post-handshake widget output**

The capture demonstrates that the renderer is now actively producing
ANSI escape sequences and cell paints inside the SSH channel, which
the antipattern was preventing entirely. The widget tree is being
walked, `paint_widget_cells` is emitting per-cell `\x1b[<r>;<c>H<ch>`
sequences for the splash widget's background fill (3,599 cell paints
in the captured stream), and the SGR background colour
(`\x1b[48;5;232m`) is being applied. This is the exact behaviour the
QA report flagged as missing in Phase 16a (`/tmp/qa_evidence/phase16a_session.log`).

The fix replaced the broken `Arc::get_mut(&mut self.renderer.clone())`
pattern (always returns `None` because cloning bumps the strong
count) with a proper `Mutex<TuiSshRenderer>` interior-mutability
pattern, exactly as the QA report's Suggested Fix recommended.

## Issue #2 — hnwatch redirect parser 307 vs 200 + numeric-id parsing

**Evidence file**: `issue2_hnwatch_runtime_441884bytes.bin` (441,884 bytes)

**Pre-fix baseline**: status bar locked at `I:0 R:0 B:0 E:0` indefinitely
**Post-fix capture**: status bar progresses
`I:0 R:0 B:0 E:0` →
`I:216 R:247 B:45780 E:0` →
`I:285 R:355 B:170400 E:0` →
`I:331 R:432 B:210371 E:0`

The capture shows real Hacker News stories rendering in the data grid,
including dynamic point-count updates across polling cycles
(e.g., "Ghostty Is Leaving GitHub" progressing 29 pts → 41 pts → 52 pts
across consecutive 15-second poll cycles). The story list visible in
the capture matches the live HN top-stories order at capture time,
including titles such as:

* "Ghostty Is Leaving GitHub"
* "DOOM running in ChatGPT"
* "Bankruptcies increase 11.9 percent"
* "GitHub Copilot code review will start consuming"
* "ASML became the chokepoint for cutting-edge"
* "Foreign-Owned Post-Merger"

Two source-code changes combined to achieve this end-to-end behaviour:

1. **Redirect parser** (`crates/hnwatch/src/eventstream.rs`): added the
   `REDIRECT_200_PATTERN` constant, the `RedirectAction` enum, and the
   `ControlFlow::StreamHere(body_offset)` variant so that 200-OK
   responses are streamed in place rather than rejected. This resolves
   the literal Issue #2 root cause flagged in the QA report.
2. **Numeric-id parsing** (`crates/hnwatch/src/hnmodel.rs`): the
   `on_mainstream` and `on_updatestream` callbacks were rejecting every
   item because the live HN API returns JSON **integers** in topic
   arrays (e.g., `[47939079, 47933208, ...]`), but the code only
   matched `JsonValue::String`. Both callbacks now accept either
   `JsonValue::String` or `JsonValue::Number` (the latter converted
   via `n.to_string()`).
