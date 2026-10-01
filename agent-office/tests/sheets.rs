//! HUP-S10.2 — CSV and XLSX formats for the Hermes sheet tools.

use citrate_agent_office::{
    format_for, read_sheet, write_sheet, Cell, Limits, OfficeError, SheetFormat,
};
use std::path::Path;

fn text(s: &str) -> Cell {
    Cell::Text(s.to_string())
}

fn rows() -> Vec<Vec<Cell>> {
    vec![
        vec![text("name"), text("amount"), text("paid")],
        vec![text("Ada"), Cell::Number(12.5), Cell::Bool(true)],
        vec![text("Lin, Bo"), Cell::Number(-3.0), Cell::Empty],
    ]
}

#[test]
fn the_format_comes_from_the_extension_case_insensitively() {
    assert_eq!(
        format_for(Path::new("/a/b.csv")).ok(),
        Some(SheetFormat::Csv)
    );
    assert_eq!(
        format_for(Path::new("/a/B.XLSX")).ok(),
        Some(SheetFormat::Xlsx)
    );
    for p in ["/a/b.xls", "/a/b.ods", "/a/b", "/a/b.txt", "/a/.csv.exe"] {
        assert!(
            matches!(
                format_for(Path::new(p)),
                Err(OfficeError::UnsupportedFormat(_))
            ),
            "{p}"
        );
    }
}

#[test]
fn csv_round_trips_text_numbers_and_quoting() {
    let bytes = write_sheet(SheetFormat::Csv, None, &rows(), &Limits::default()).unwrap();
    let text_out = String::from_utf8(bytes.clone()).unwrap();
    assert!(text_out.contains("\"Lin, Bo\""), "{text_out}");
    let back = read_sheet(SheetFormat::Csv, &bytes, None, &Limits::default()).unwrap();
    assert_eq!(back.rows[0], rows()[0]);
    // CSV has no types: numbers come back as numbers, a boolean as its text.
    assert_eq!(back.rows[1][1], Cell::Number(12.5));
    assert_eq!(back.rows[1][2], text("true"));
    assert_eq!(back.rows[2][0], text("Lin, Bo"));
    assert_eq!(back.rows[2][1], Cell::Number(-3.0));
    assert_eq!(back.rows[2][2], Cell::Empty);
    assert!(!back.truncated);
    assert_eq!(back.sheet_names, Vec::<String>::new());
}

#[test]
fn csv_ragged_rows_are_kept_as_they_are() {
    let bytes = b"a,b,c\n1\n2,3\n";
    let s = read_sheet(SheetFormat::Csv, bytes, None, &Limits::default()).unwrap();
    assert_eq!(s.rows.len(), 3);
    assert_eq!(s.rows[1], vec![Cell::Number(1.0)]);
    assert_eq!(s.rows[2].len(), 2);
}

#[test]
fn csv_written_text_that_a_spreadsheet_would_run_as_a_formula_is_neutralised() {
    let r = vec![vec![
        text("=HYPERLINK(\"x\")"),
        text("+1+1"),
        text("@SUM(A1)"),
        text("-2+3"),
        text("-7"),
        text("plain"),
    ]];
    let out =
        String::from_utf8(write_sheet(SheetFormat::Csv, None, &r, &Limits::default()).unwrap())
            .unwrap();
    let line = out.lines().next().unwrap();
    assert!(line.starts_with("\"'=HYPERLINK"), "{line}");
    assert!(line.contains(",'+1+1,"), "{line}");
    assert!(line.contains(",'@SUM(A1),"), "{line}");
    assert!(line.contains(",'-2+3,"), "{line}");
    // A plain negative number written as text stays a number.
    assert!(line.contains(",-7,"), "{line}");
    assert!(line.ends_with(",plain"), "{line}");
}

#[test]
fn xlsx_round_trips_types_and_sheet_names() {
    let bytes = write_sheet(
        SheetFormat::Xlsx,
        Some("Budget"),
        &rows(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(&bytes[..2], b"PK");
    let back = read_sheet(SheetFormat::Xlsx, &bytes, None, &Limits::default()).unwrap();
    assert_eq!(back.sheet_names, vec!["Budget".to_string()]);
    assert_eq!(back.sheet.as_deref(), Some("Budget"));
    assert_eq!(back.rows[0], rows()[0]);
    assert_eq!(
        back.rows[1],
        vec![text("Ada"), Cell::Number(12.5), Cell::Bool(true)]
    );
    assert_eq!(back.rows[2][0], text("Lin, Bo"));
    assert_eq!(back.rows[2][1], Cell::Number(-3.0));
}

#[test]
fn xlsx_text_that_looks_like_a_formula_stays_text() {
    let r = vec![vec![text("=1+1")]];
    let bytes = write_sheet(SheetFormat::Xlsx, None, &r, &Limits::default()).unwrap();
    let back = read_sheet(SheetFormat::Xlsx, &bytes, None, &Limits::default()).unwrap();
    assert_eq!(back.rows[0][0], text("=1+1"));
}

#[test]
fn xlsx_reads_a_named_sheet_and_refuses_an_unknown_one() {
    let bytes = write_sheet(SheetFormat::Xlsx, Some("Q3"), &rows(), &Limits::default()).unwrap();
    assert!(read_sheet(SheetFormat::Xlsx, &bytes, Some("Q3"), &Limits::default()).is_ok());
    match read_sheet(SheetFormat::Xlsx, &bytes, Some("Q4"), &Limits::default()) {
        Err(OfficeError::NoSuchSheet { wanted, available }) => {
            assert_eq!(wanted, "Q4");
            assert_eq!(available, vec!["Q3".to_string()]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn reading_stops_at_the_row_and_column_limits_and_says_so() {
    let mut csv = String::new();
    for i in 0..50 {
        csv.push_str(&format!("{i},a,b,c,d\n"));
    }
    let limits = Limits {
        max_rows: 10,
        max_cols: 3,
        ..Limits::default()
    };
    let s = read_sheet(SheetFormat::Csv, csv.as_bytes(), None, &limits).unwrap();
    assert_eq!(s.rows.len(), 10);
    assert!(s.rows.iter().all(|r| r.len() <= 3));
    assert!(s.truncated);
}

#[test]
fn long_cells_are_cut_when_read() {
    let long = "x".repeat(5000);
    let csv = format!("{long}\n");
    let limits = Limits {
        max_cell_chars: 100,
        ..Limits::default()
    };
    let s = read_sheet(SheetFormat::Csv, csv.as_bytes(), None, &limits).unwrap();
    match &s.rows[0][0] {
        Cell::Text(t) => assert_eq!(t.chars().count(), 100),
        c => panic!("{c:?}"),
    }
    assert!(s.truncated);
}

#[test]
fn input_larger_than_the_byte_limit_is_refused() {
    let limits = Limits {
        max_bytes: 16,
        ..Limits::default()
    };
    let r = read_sheet(SheetFormat::Csv, &[b'a'; 17], None, &limits);
    assert!(matches!(r, Err(OfficeError::TooLarge { .. })), "{r:?}");
}

#[test]
fn writing_more_than_the_limits_is_refused_not_cut() {
    let limits = Limits {
        max_rows: 2,
        ..Limits::default()
    };
    let r = write_sheet(SheetFormat::Csv, None, &rows(), &limits);
    assert!(matches!(r, Err(OfficeError::TooLarge { .. })), "{r:?}");
    let limits = Limits {
        max_cell_chars: 3,
        ..Limits::default()
    };
    let r = write_sheet(SheetFormat::Xlsx, None, &rows(), &limits);
    assert!(matches!(r, Err(OfficeError::TooLarge { .. })), "{r:?}");
}

#[test]
fn a_bad_sheet_name_is_refused() {
    for name in ["", "a/b", "a[b]", "x".repeat(32).as_str(), "'quoted"] {
        let r = write_sheet(SheetFormat::Xlsx, Some(name), &rows(), &Limits::default());
        assert!(matches!(r, Err(OfficeError::Invalid(_))), "{name}: {r:?}");
    }
}

#[test]
fn a_non_finite_number_is_refused() {
    let r = vec![vec![Cell::Number(f64::NAN)]];
    for f in [SheetFormat::Csv, SheetFormat::Xlsx] {
        assert!(matches!(
            write_sheet(f, None, &r, &Limits::default()),
            Err(OfficeError::Invalid(_))
        ));
    }
}

#[test]
fn garbage_is_not_a_workbook() {
    let r = read_sheet(
        SheetFormat::Xlsx,
        b"PK\x03\x04garbage",
        None,
        &Limits::default(),
    );
    assert!(matches!(r, Err(OfficeError::Unreadable(_))), "{r:?}");
}

#[test]
fn a_workbook_whose_parts_inflate_past_the_limit_is_refused_before_inflating() {
    // A real workbook with one big, very compressible cell: small on disk, large inflated.
    let r: Vec<Vec<Cell>> = (0..300)
        .map(|_| vec![Cell::Text("a".repeat(100))])
        .collect();
    let bytes = write_sheet(SheetFormat::Xlsx, None, &r, &Limits::default()).unwrap();
    assert!(bytes.len() < 30_000);
    let limits = Limits {
        max_inflated_bytes: 20_000,
        ..Limits::default()
    };
    let res = read_sheet(SheetFormat::Xlsx, &bytes, None, &limits);
    assert!(matches!(res, Err(OfficeError::TooLarge { .. })), "{res:?}");
}

#[test]
fn csv_that_is_not_utf8_is_refused() {
    let r = read_sheet(
        SheetFormat::Csv,
        &[0xff, 0xfe, b',', 0x00],
        None,
        &Limits::default(),
    );
    assert!(matches!(r, Err(OfficeError::Unreadable(_))), "{r:?}");
}

#[test]
fn cells_serialise_as_plain_json_values() {
    let v = serde_json::to_value(rows()).unwrap();
    assert_eq!(v[1], serde_json::json!(["Ada", 12.5, true]));
    assert_eq!(v[2][2], serde_json::Value::Null);
    let back: Vec<Vec<Cell>> = serde_json::from_value(v).unwrap();
    assert_eq!(back, rows());
}

#[test]
fn cutting_only_columns_still_says_truncated() {
    let limits = Limits {
        max_cols: 2,
        ..Limits::default()
    };
    let s = read_sheet(SheetFormat::Csv, b"a,b,c\n", None, &limits).unwrap();
    assert_eq!(s.rows[0].len(), 2);
    assert!(s.truncated);
    let s = read_sheet(SheetFormat::Csv, b"a,b\n", None, &limits).unwrap();
    assert!(!s.truncated);
}

#[test]
fn xlsx_keeps_cell_positions_when_the_sheet_starts_below_and_right_of_a1() {
    let r = vec![vec![], vec![Cell::Empty, text("x")]];
    let bytes = write_sheet(SheetFormat::Xlsx, None, &r, &Limits::default()).unwrap();
    let back = read_sheet(SheetFormat::Xlsx, &bytes, None, &Limits::default()).unwrap();
    assert_eq!(back.rows, r);
}
