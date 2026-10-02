---
created: 2026-10-01
branch: hup/n4-browser
author: Larry Klosowski + Claude Opus 5.5
status: recorded fixture
---

# Fixtures

`ax-login-form.json` is the `Accessibility.getFullAXTree` result for the `LOGIN` page in
`../common/mod.rs`, recorded from headless Chrome 154 on macOS by
`CITRATE_RECORD_FIXTURES=1 cargo test -p citrate-agent-browser --test live_chrome_tests`.
It lets the snapshot builder be tested on a real tree on machines with no Chromium.
