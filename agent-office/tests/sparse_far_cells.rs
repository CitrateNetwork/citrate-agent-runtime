//! HUP-S10.2 review: a workbook whose few cells sit far apart must be read in bounded memory.
//!
//! The reader holds only the cells inside the read limits, whatever the sheet's layout. This test
//! binary refuses any single allocation over 256 MiB, so the test also fails if reading a small
//! file ever needs a large buffer.

use std::alloc::{GlobalAlloc, Layout, System};

use citrate_agent_office::{read_sheet, Cell, Limits, SheetFormat};

struct Capped;

const CAP: usize = 256 * 1024 * 1024;

// SAFETY: every call is forwarded to the system allocator unchanged, except that a request over
// CAP returns null, which callers handle as an allocation failure.
unsafe impl GlobalAlloc for Capped {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if l.size() > CAP {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        if l.size() > CAP {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if new > CAP {
            return std::ptr::null_mut();
        }
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static ALLOC: Capped = Capped;

#[test]
fn a_workbook_with_two_far_apart_cells_is_read_in_bounded_memory() {
    let mut wb = rust_xlsxwriter::Workbook::new();
    let ws = wb.add_worksheet();
    ws.write_string(0, 0, "top left").unwrap();
    ws.write_string(2, 1, "near").unwrap();
    // The last cell an .xlsx sheet can hold.
    ws.write_string(1_048_575, 16_383, "far").unwrap();
    let bytes = wb.save_to_buffer().unwrap();

    let data = read_sheet(SheetFormat::Xlsx, &bytes, None, &Limits::default()).unwrap();
    assert_eq!(data.rows[0], vec![Cell::Text("top left".into())]);
    assert_eq!(data.rows[2], vec![Cell::Empty, Cell::Text("near".into())]);
    assert_eq!(
        data.rows.len(),
        3,
        "rows past the last kept cell are not padded"
    );
    assert!(
        data.truncated,
        "the far cell is past the limits, so the result says so"
    );
}
