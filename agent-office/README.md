---
created: 2026-10-01T00:00:00Z
branch: hup/n4-media-sheets
author: Larry Klosowski + Claude Opus 5.5
status: implemented (used by the sidecar sheet tools)
---

# citrate-agent-office

Spreadsheet formats for the Hermes sheet tools (HUP-S10.2, US-10.2 AC1): bounded `.csv` and
`.xlsx` reading and writing over bytes.

This crate never touches a path. The sidecar's `sheet_read` / `sheet_write` tools
(`agent-sidecar/src/sheets.rs`) check every path against the member's folder grants
(`citrate-agent-grants`, deny list first) at the moment of use, do the I/O on the canonical path,
and hand the bytes here.

## Guarantees

| Property | How |
|---|---|
| Bounded input | over `max_bytes` refused; every `.xlsx` part is inflated and counted before calamine parses it, refused past `max_inflated_bytes` (declared sizes are not trusted) |
| Bounded output | rows, columns and cell text over the limits are cut on read (`truncated: true`) and refused whole on write |
| No formulas written | `.xlsx` cells are written as string, number or boolean; CSV text that a spreadsheet would run (`= + - @`, tab, CR, unless a plain number) gets a leading apostrophe |
| Values read, not formulas | `.xlsx` returns cached values; dates as their displayed text |
| Cell positions kept | an `.xlsx` range that starts below or right of A1 is padded so row/column indexes match the sheet |

Limits (`Limits::default()` and the sidecar's `SHEET_LIMITS`) are conservative defaults, pending
owner sign-off: 10 MiB files, 64 MiB inflated workbook, 5,000 rows, 200 columns, 8,192 characters
per cell.

Dependencies: `csv` (Unlicense/MIT), `calamine` (MIT), `rust_xlsxwriter` (MIT/Apache-2.0), `zip`
(MIT, already pulled in by both).

Keyless: nothing here signs (Rule 3).
