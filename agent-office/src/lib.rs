//! # citrate-agent-office: spreadsheet formats for the Hermes sheet tools (HUP-S10.2)
//!
//! Hermes reads and writes the member's spreadsheets (`.csv`, `.xlsx`) inside folders the member
//! granted. This crate is the format half of that: bytes in, rows out, and rows in, bytes out,
//! always inside [`Limits`]. It never touches a path. The caller (the sidecar's `sheet_read` /
//! `sheet_write` tools) checks every path against the member's folder grants at the moment of
//! use and does the I/O on the canonical path the check returns.
//!
//! ## What it guarantees
//!
//! * **Bounded reads.** Input over [`Limits::max_bytes`] is refused. An `.xlsx` is a zip archive:
//!   every part is inflated here first, counting bytes, and the workbook is refused as soon as
//!   the parts together pass [`Limits::max_inflated_bytes`], before the parser sees it. Rows,
//!   columns and cell text past their limits are cut and the result says `truncated`.
//! * **Bounded writes.** A write over any limit is refused whole, never silently cut.
//! * **No formulas are ever written.** `.xlsx` cells are written as strings, numbers or
//!   booleans. In `.csv`, text a spreadsheet app would run as a formula (it starts with `=`,
//!   `+`, `-`, `@`, tab or carriage return and is not a plain number) is written with a leading
//!   apostrophe, so opening the file never runs it.
//! * **Values, not formulas, are read.** For `.xlsx` the cached value of a formula cell is
//!   returned (what the member sees), dates as their displayed ISO text.
//!
//! Keyless: nothing here signs or holds a key (Rule 3).

use std::io::{Cursor, Read};
use std::path::Path;

use calamine::{Data, Reader};
use serde::{Deserialize, Serialize};

/// The formats the sheet tools handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SheetFormat {
    Csv,
    Xlsx,
}

/// One cell. Serialises as a plain JSON value: `null`, a string, a number or a boolean.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Cell {
    Empty,
    Bool(bool),
    Number(f64),
    Text(String),
}

/// Size limits. The defaults are conservative, pending owner sign-off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest input file, and largest output, in bytes.
    pub max_bytes: u64,
    /// Largest total inflated size of an `.xlsx` archive's parts, in bytes.
    pub max_inflated_bytes: u64,
    /// Most rows read or written.
    pub max_rows: usize,
    /// Most columns per row read or written.
    pub max_cols: usize,
    /// Longest cell text, in characters.
    pub max_cell_chars: usize,
}

impl Default for Limits {
    fn default() -> Self {
        // Conservative defaults, pending owner sign-off.
        Limits {
            max_bytes: 10 * 1024 * 1024,
            max_inflated_bytes: 64 * 1024 * 1024,
            max_rows: 5_000,
            max_cols: 200,
            max_cell_chars: 8_192,
        }
    }
}

/// A sheet that was read.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SheetData {
    /// Every sheet in the workbook (empty for CSV, which has none).
    pub sheet_names: Vec<String>,
    /// The sheet that was read (`None` for CSV).
    pub sheet: Option<String>,
    pub rows: Vec<Vec<Cell>>,
    /// True when rows, columns or cell text were cut at the limits.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OfficeError {
    #[error("{0} is not a spreadsheet the sheet tools handle (use .csv or .xlsx)")]
    UnsupportedFormat(String),
    #[error("{what} is over the limit of {limit}")]
    TooLarge { what: String, limit: u64 },
    #[error("there is no sheet named {wanted:?} (sheets: {available:?})")]
    NoSuchSheet {
        wanted: String,
        available: Vec<String>,
    },
    #[error("the workbook has no sheets")]
    NoSheets,
    #[error("the file could not be read as this format: {0}")]
    Unreadable(String),
    #[error("{0}")]
    Invalid(String),
}

type Result<T> = std::result::Result<T, OfficeError>;

/// The format of `path`, from its extension (case-insensitive).
pub fn format_for(path: &Path) -> Result<SheetFormat> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("csv") => Ok(SheetFormat::Csv),
        Some("xlsx") => Ok(SheetFormat::Xlsx),
        _ => Err(OfficeError::UnsupportedFormat(path.display().to_string())),
    }
}

/// Read a sheet from `bytes`. `sheet` picks an `.xlsx` sheet by name (default: the first); it is
/// ignored for CSV.
pub fn read_sheet(
    format: SheetFormat,
    bytes: &[u8],
    sheet: Option<&str>,
    limits: &Limits,
) -> Result<SheetData> {
    if bytes.len() as u64 > limits.max_bytes {
        return Err(OfficeError::TooLarge {
            what: format!("the file ({} bytes)", bytes.len()),
            limit: limits.max_bytes,
        });
    }
    match format {
        SheetFormat::Csv => read_csv(bytes, limits),
        SheetFormat::Xlsx => read_xlsx(bytes, sheet, limits),
    }
}

/// Serialise `rows` as `format`. `sheet` names the `.xlsx` sheet (default `Sheet1`); it is
/// ignored for CSV. Anything over the limits is refused whole.
pub fn write_sheet(
    format: SheetFormat,
    sheet: Option<&str>,
    rows: &[Vec<Cell>],
    limits: &Limits,
) -> Result<Vec<u8>> {
    check_write(rows, limits)?;
    let out = match format {
        SheetFormat::Csv => write_csv(rows)?,
        SheetFormat::Xlsx => write_xlsx(sheet, rows)?,
    };
    if out.len() as u64 > limits.max_bytes {
        return Err(OfficeError::TooLarge {
            what: format!("the written file ({} bytes)", out.len()),
            limit: limits.max_bytes,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// Collects rows within the limits and remembers whether anything was cut.
struct Collector<'a> {
    limits: &'a Limits,
    rows: Vec<Vec<Cell>>,
    truncated: bool,
}

impl<'a> Collector<'a> {
    fn new(limits: &'a Limits) -> Self {
        Collector {
            limits,
            rows: Vec::new(),
            truncated: false,
        }
    }

    /// False once the row limit is reached (the caller stops).
    fn has_room(&mut self) -> bool {
        if self.rows.len() >= self.limits.max_rows {
            self.truncated = true;
            return false;
        }
        true
    }

    fn push(&mut self, row: impl Iterator<Item = Cell>) {
        let mut out = Vec::new();
        for cell in row {
            if out.len() >= self.limits.max_cols {
                self.truncated = true;
                break;
            }
            out.push(self.cut(cell));
        }
        self.rows.push(out);
    }

    fn cut(&mut self, cell: Cell) -> Cell {
        match cell {
            Cell::Text(t) if t.chars().count() > self.limits.max_cell_chars => {
                self.truncated = true;
                Cell::Text(t.chars().take(self.limits.max_cell_chars).collect())
            }
            c => c,
        }
    }
}

/// A CSV field as a cell: empty, a finite number, or text.
fn csv_cell(field: &str) -> Cell {
    if field.is_empty() {
        return Cell::Empty;
    }
    match field.trim().parse::<f64>() {
        Ok(n) if n.is_finite() && looks_numeric(field.trim()) => Cell::Number(n),
        _ => Cell::Text(field.to_string()),
    }
}

/// Only plain decimal notation counts as a number (Rust also parses "inf", "NaN", "1e5").
fn looks_numeric(s: &str) -> bool {
    let s = s.strip_prefix(['-', '+']).unwrap_or(s);
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_digit() || c == '.')
        && s.chars().filter(|c| *c == '.').count() <= 1
        && s.chars().any(|c| c.is_ascii_digit())
}

fn read_csv(bytes: &[u8], limits: &Limits) -> Result<SheetData> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| OfficeError::Unreadable("the CSV is not UTF-8 text".into()))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());
    let mut c = Collector::new(limits);
    for rec in rdr.records() {
        let rec = rec.map_err(|e| OfficeError::Unreadable(e.to_string()))?;
        if !c.has_room() {
            break;
        }
        c.push(rec.iter().map(csv_cell));
    }
    Ok(SheetData {
        sheet_names: Vec::new(),
        sheet: None,
        rows: c.rows,
        truncated: c.truncated,
    })
}

/// Inflate every part of the archive, counting, and refuse it once the total passes the limit.
/// Declared sizes are not trusted: the bytes are counted as they come out.
fn check_inflated_size(bytes: &[u8], limit: u64) -> Result<()> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| OfficeError::Unreadable(format!("not a workbook: {e}")))?;
    let mut total: u64 = 0;
    for i in 0..zip.len() {
        let mut part = zip
            .by_index(i)
            .map_err(|e| OfficeError::Unreadable(format!("not a workbook: {e}")))?;
        let budget = limit.saturating_sub(total);
        let n = std::io::copy(&mut (&mut part).take(budget + 1), &mut std::io::sink())
            .map_err(|e| OfficeError::Unreadable(format!("not a workbook: {e}")))?;
        total = total.saturating_add(n);
        if total > limit {
            return Err(OfficeError::TooLarge {
                what: "the workbook's inflated contents".into(),
                limit,
            });
        }
    }
    Ok(())
}

fn xlsx_cell(d: &Data) -> Cell {
    match d {
        Data::Empty => Cell::Empty,
        Data::Bool(b) => Cell::Bool(*b),
        Data::Int(i) => Cell::Number(*i as f64),
        Data::Float(f) if f.is_finite() => Cell::Number(*f),
        Data::String(s) => Cell::Text(s.clone()),
        other => Cell::Text(other.to_string()),
    }
}

fn read_xlsx(bytes: &[u8], sheet: Option<&str>, limits: &Limits) -> Result<SheetData> {
    check_inflated_size(bytes, limits.max_inflated_bytes)?;
    let mut wb: calamine::Xlsx<_> = calamine::open_workbook_from_rs(Cursor::new(bytes))
        .map_err(|e| OfficeError::Unreadable(format!("not a workbook: {e}")))?;
    let names = wb.sheet_names();
    let name = match sheet {
        Some(wanted) => names
            .iter()
            .find(|n| n.as_str() == wanted)
            .cloned()
            .ok_or_else(|| OfficeError::NoSuchSheet {
                wanted: wanted.to_string(),
                available: names.clone(),
            })?,
        None => names.first().cloned().ok_or(OfficeError::NoSheets)?,
    };
    // Cells are streamed and only those inside the limits are kept, so memory follows the
    // limits, not the sheet's layout. Positions are kept: a cell's row and column indexes match
    // the sheet.
    let mut cells = wb
        .worksheet_cells_reader(&name)
        .map_err(|e| OfficeError::Unreadable(e.to_string()))?;
    let mut c = Collector::new(limits);
    while let Some(cell) = cells
        .next_cell()
        .map_err(|e| OfficeError::Unreadable(e.to_string()))?
    {
        let (r, col) = cell.get_position();
        let (r, col) = (r as usize, col as usize);
        if r >= limits.max_rows || col >= limits.max_cols {
            c.truncated = true;
            continue;
        }
        let value = c.cut(xlsx_cell(&Data::from(cell.get_value().clone())));
        if value == Cell::Empty {
            continue;
        }
        if c.rows.len() <= r {
            c.rows.resize(r + 1, Vec::new());
        }
        let row = &mut c.rows[r];
        if row.len() <= col {
            row.resize(col + 1, Cell::Empty);
        }
        row[col] = value;
    }
    Ok(SheetData {
        sheet_names: names,
        sheet: Some(name),
        rows: c.rows,
        truncated: c.truncated,
    })
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

fn check_write(rows: &[Vec<Cell>], limits: &Limits) -> Result<()> {
    if rows.len() > limits.max_rows {
        return Err(OfficeError::TooLarge {
            what: format!("{} rows", rows.len()),
            limit: limits.max_rows as u64,
        });
    }
    for (i, row) in rows.iter().enumerate() {
        if row.len() > limits.max_cols {
            return Err(OfficeError::TooLarge {
                what: format!("row {} ({} columns)", i + 1, row.len()),
                limit: limits.max_cols as u64,
            });
        }
        for cell in row {
            match cell {
                Cell::Text(t) if t.chars().count() > limits.max_cell_chars => {
                    return Err(OfficeError::TooLarge {
                        what: format!("a cell in row {} ({} characters)", i + 1, t.chars().count()),
                        limit: limits.max_cell_chars as u64,
                    })
                }
                Cell::Number(n) if !n.is_finite() => {
                    return Err(OfficeError::Invalid(format!(
                        "row {} has a number that is not finite",
                        i + 1
                    )))
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Text a spreadsheet app would run as a formula gets a leading apostrophe (OWASP CSV injection).
fn neutralise(text: &str) -> std::borrow::Cow<'_, str> {
    let risky = text.starts_with(['=', '+', '-', '@', '\t', '\r']);
    if risky && !looks_numeric(text) {
        std::borrow::Cow::Owned(format!("'{text}"))
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}

fn number_text(n: f64) -> String {
    // Integers print without a trailing ".0"; f64 Display never uses exponent notation.
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

fn write_csv(rows: &[Vec<Cell>]) -> Result<Vec<u8>> {
    let mut w = csv::WriterBuilder::new()
        .flexible(true)
        .terminator(csv::Terminator::Any(b'\n'))
        .from_writer(Vec::new());
    for row in rows {
        let fields: Vec<String> = row
            .iter()
            .map(|c| match c {
                Cell::Empty => String::new(),
                Cell::Bool(b) => b.to_string(),
                Cell::Number(n) => number_text(*n),
                Cell::Text(t) => neutralise(t).into_owned(),
            })
            .collect();
        w.write_record(&fields)
            .map_err(|e| OfficeError::Invalid(e.to_string()))?;
    }
    w.into_inner()
        .map_err(|e| OfficeError::Invalid(e.to_string()))
}

/// Excel's sheet-name rules: 1 to 31 characters, none of `[]:*?/\`, not starting or ending with
/// an apostrophe.
fn valid_sheet_name(name: &str) -> bool {
    let n = name.chars().count();
    (1..=31).contains(&n)
        && !name.contains(['[', ']', ':', '*', '?', '/', '\\'])
        && !name.starts_with('\'')
        && !name.ends_with('\'')
}

fn write_xlsx(sheet: Option<&str>, rows: &[Vec<Cell>]) -> Result<Vec<u8>> {
    let name = sheet.unwrap_or("Sheet1");
    if !valid_sheet_name(name) {
        return Err(OfficeError::Invalid(format!(
            "{name:?} is not a valid sheet name (1 to 31 characters, none of []:*?/\\)"
        )));
    }
    let mut wb = rust_xlsxwriter::Workbook::new();
    let ws = wb.add_worksheet();
    ws.set_name(name)
        .map_err(|e| OfficeError::Invalid(e.to_string()))?;
    let xerr = |e: rust_xlsxwriter::XlsxError| OfficeError::Invalid(e.to_string());
    for (r, row) in rows.iter().enumerate() {
        let r = u32::try_from(r).map_err(|_| OfficeError::Invalid("too many rows".into()))?;
        for (c, cell) in row.iter().enumerate() {
            let c =
                u16::try_from(c).map_err(|_| OfficeError::Invalid("too many columns".into()))?;
            match cell {
                Cell::Empty => {}
                Cell::Bool(b) => {
                    ws.write_boolean(r, c, *b).map_err(xerr)?;
                }
                Cell::Number(n) => {
                    ws.write_number(r, c, *n).map_err(xerr)?;
                }
                // write_string stores text as text: a leading "=" is never a formula.
                Cell::Text(t) => {
                    ws.write_string(r, c, t).map_err(xerr)?;
                }
            }
        }
    }
    wb.save_to_buffer().map_err(xerr)
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn only_plain_decimals_are_numbers() {
        for s in ["1", "-1", "+2.5", "0.25", "10."] {
            assert!(looks_numeric(s), "{s}");
        }
        for s in ["inf", "NaN", "1e5", "", "-", "1.2.3", "0x10", "1,000"] {
            assert!(!looks_numeric(s), "{s}");
        }
    }

    #[test]
    fn whole_numbers_print_without_a_fraction() {
        assert_eq!(number_text(3.0), "3");
        assert_eq!(number_text(-0.5), "-0.5");
    }

    #[test]
    fn sheet_name_rules() {
        assert!(valid_sheet_name("Budget 2026"));
        assert!(!valid_sheet_name("a:b"));
        assert!(!valid_sheet_name("end'"));
    }
}
