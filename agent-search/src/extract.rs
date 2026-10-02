//! Local readability: HTML in, the main content as markdown out. No network, no third party.
//!
//! The article pass is `dom_smoothie` (a Rust port of Mozilla's Readability, MIT). When it finds
//! no article (short pages, app shells), the whole body is converted instead, minus scripts,
//! styles, navigation, forms and other chrome.

use dom_query::Document;
use dom_smoothie::{Config, Readability, TextMode};

/// Elements dropped by the whole-body fallback.
const SKIP: &[&str] = &[
    "script", "style", "meta", "head", "noscript", "template", "svg", "iframe", "nav", "footer",
    "form", "button", "select", "canvas", "object", "embed",
];

/// Page chrome removed before the article pass.
const CHROME: &str =
    "nav, footer, aside, form, script, style, noscript, template, iframe, svg, canvas, object, embed, button, select, dialog";

/// Upper bound on elements the article pass scores (bounds CPU on hostile pages).
const MAX_ELEMENTS: usize = 50_000;

/// The extracted page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    pub title: Option<String>,
    pub markdown: String,
}

fn tidy(md: &str) -> String {
    let mut out = String::with_capacity(md.len());
    let mut blank = 0;
    for line in md.lines() {
        let l = line.trim_end();
        if l.trim().is_empty() {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        out.push_str(l);
        out.push('\n');
    }
    out.trim().to_string()
}

/// The markdown serializer escapes punctuation for renderers ("line\\."); the reader is a model,
/// so plain punctuation is easier to read and cheaper in tokens.
fn unescape(md: &str) -> String {
    let mut out = String::with_capacity(md.len());
    let mut chars = md.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&n) = chars.peek() {
                if matches!(
                    n,
                    '.' | '!'
                        | '('
                        | ')'
                        | '-'
                        | '+'
                        | '#'
                        | '_'
                        | '*'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '`'
                        | '>'
                        | '|'
                        | '~'
                ) {
                    out.push(n);
                    chars.next();
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

fn non_empty(s: &str) -> Option<String> {
    let t = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

/// Extract the main content of `html` as markdown. `url` (absolute) resolves relative links.
pub fn extract_markdown(html: &str, url: Option<&str>) -> Extracted {
    let cfg = Config {
        text_mode: TextMode::Markdown,
        max_elements_to_parse: MAX_ELEMENTS,
        ..Config::default()
    };
    let doc_title = non_empty(&Document::from(html).select("title").text());
    let stripped = || {
        let d = Document::from(html);
        d.select(CHROME).remove();
        d
    };
    let article = Readability::with_document(stripped(), url, Some(cfg.clone()))
        .or_else(|_| Readability::with_document(stripped(), None, Some(cfg)))
        .ok()
        .and_then(|mut r| r.parse().ok());
    if let Some(a) = article {
        let md = tidy(&unescape(&a.text_content));
        if !md.is_empty() {
            return Extracted {
                title: non_empty(&a.title).or(doc_title),
                markdown: md,
            };
        }
    }
    let doc = Document::from(html);
    let body = doc.select("body");
    let md = if body.exists() {
        body.nodes()
            .first()
            .map(|n| n.md(Some(SKIP)).to_string())
            .unwrap_or_default()
    } else {
        doc.md(Some(SKIP)).to_string()
    };
    Extracted {
        title: doc_title,
        markdown: tidy(&unescape(&md)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_body_fallback_drops_chrome() {
        let ex = extract_markdown(
            "<html><head><title> T </title></head><body><nav>menu</nav><h1>Hi</h1><p>One line.</p><script>x()</script><footer>foot</footer></body></html>",
            None,
        );
        assert_eq!(ex.title.as_deref(), Some("T"));
        assert!(ex.markdown.contains("Hi"));
        assert!(ex.markdown.contains("One line."), "{:?}", ex);
        assert!(!ex.markdown.contains("menu"));
        assert!(!ex.markdown.contains("x()"));
        assert!(!ex.markdown.contains("foot"));
    }

    #[test]
    fn empty_and_garbage_input_do_not_panic() {
        for h in [
            "",
            "<",
            "<<<>>>",
            "\u{0}\u{1}",
            "<html><body></body></html>",
        ] {
            let _ = extract_markdown(h, Some("https://example.com/"));
        }
    }

    #[test]
    fn unescape_keeps_text_readable() {
        assert_eq!(
            unescape(r"One line\. A \(b\) c\\d"),
            r"One line. A (b) c\\d"
        );
    }

    #[test]
    fn tidy_collapses_blank_runs() {
        assert_eq!(tidy("a\n\n\n\nb  \n"), "a\n\nb");
    }
}
