# CLAUDE.md

- Respond in Japanese
- Source code, comments, logs, error messages: English
- Create feature branch → commit → push → PR (merge is done by humans)
- All PR review comments must be replied to and resolved before merging

## CI Notes

- CI uses `-Dwarnings` so all warnings are treated as errors
- For WIP modules, add `#![allow(dead_code)]` at module top
- Doc comments: `[X]` is interpreted as a link reference by rustdoc; escape as `\[X\]`
