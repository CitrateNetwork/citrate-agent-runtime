//! HUP-S5.1: the screencast buffer the Browser pop-out reads.
//!
//! Holds the latest frame only (a viewer that falls behind skips frames, it never queues them),
//! plus the element Hermes is about to act on or just acted on, so the pop-out can outline it.
//! Every change bumps one version number; a reader asks for "anything newer than N".

use std::sync::Mutex;

use serde::Serialize;

/// An element outline, in CSS pixels of the page viewport.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Highlight {
    pub r#ref: String,
    pub label: String,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    /// `pending` while the member is asked, `acted` after the action ran.
    pub state: String,
}

/// What the pop-out shows.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameView {
    pub version: u64,
    /// `image/jpeg`, base64 (as CDP sends it). Empty when withheld or before the first frame.
    pub mime: String,
    pub data: String,
    /// The page viewport size the frame shows, in CSS pixels.
    pub viewport_width: f64,
    pub viewport_height: f64,
    pub url: String,
    /// True when the frame is held back (attach mode, an origin without consent).
    pub withheld: bool,
    pub highlight: Option<Highlight>,
}

#[derive(Debug, Default)]
struct Inner {
    version: u64,
    mime: String,
    data: String,
    viewport: (f64, f64),
    url: String,
    withheld: bool,
    highlight: Option<Highlight>,
}

/// The latest-frame buffer.
#[derive(Debug, Default)]
pub struct FrameBuffer(Mutex<Inner>);

impl FrameBuffer {
    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let mut g = match self.0.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        f(&mut g)
    }

    /// A new frame.
    pub fn push(&self, mime: &str, data: String, viewport: (f64, f64), url: &str) {
        self.with(|s| {
            s.version += 1;
            s.mime = mime.to_string();
            s.data = data;
            s.viewport = viewport;
            s.url = url.to_string();
            s.withheld = false;
        });
    }

    /// A frame that must not be shown (its pixels are dropped).
    pub fn withhold(&self, url: &str) {
        self.with(|s| {
            s.version += 1;
            s.data.clear();
            s.url = url.to_string();
            s.withheld = true;
        });
    }

    pub fn set_highlight(&self, h: Option<Highlight>) {
        self.with(|s| {
            if s.highlight != h {
                s.version += 1;
                s.highlight = h;
            }
        });
    }

    /// Drop everything (the browser stopped or detached).
    pub fn clear(&self) {
        self.with(|s| {
            let v = s.version + 1;
            *s = Inner {
                version: v,
                ..Inner::default()
            };
        });
    }

    pub fn version(&self) -> u64 {
        self.with(|s| s.version)
    }

    /// The view when it is newer than `after`.
    pub fn newer_than(&self, after: u64) -> Option<FrameView> {
        self.with(|s| {
            (s.version > after).then(|| FrameView {
                version: s.version,
                mime: s.mime.clone(),
                data: s.data.clone(),
                viewport_width: s.viewport.0,
                viewport_height: s.viewport.1,
                url: s.url.clone(),
                withheld: s.withheld,
                highlight: s.highlight.clone(),
            })
        })
    }
}
