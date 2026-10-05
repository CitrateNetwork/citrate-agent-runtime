//! HUP-S5.2: private search and page reading as sidecar session tools (`web_search`,
//! `read_url`), registered only when `CITRATE_HERMES_SEARCH=1` (default off).
//!
//! | env                              | meaning                                                         |
//! |----------------------------------|-----------------------------------------------------------------|
//! | `CITRATE_HERMES_SEARCH`          | `1` offers `web_search` + `read_url` in every session           |
//! | `CITRATE_HERMES_SEARXNG`         | absolute path of `searxng-run` (or its virtualenv); unset = search "not installed" |
//! | `CITRATE_HERMES_SEARXNG_DATA`    | absolute folder for SearXNG's generated settings and log        |
//! | `CITRATE_HERMES_SEARXNG_ENGINES` | comma-separated engines SearXNG may load; unset = the default list, empty = none |
//! | `CITRATE_HERMES_READER`          | `jina` opts in to the Jina Reader; anything else = local reading |
//! | `CITRATE_HERMES_JINA_ENDPOINT`   | Jina Reader base URL (https), default `https://r.jina.ai/`      |
//! | `CITRATE_HERMES_JINA_KEY_FILE`   | file holding a Jina API key (optional)                          |
//!
//! Reading is local by default: the page is fetched here and extracted on this machine. The
//! tools' output is untrusted, so a call taints the session (HUP-S2.7).

use std::path::PathBuf;
use std::sync::Arc;

use citrate_agent_search::{
    engine_name_ok, JinaReader, ReaderBackend, SearchConfig, SearchHost, SearxngConfig,
    JINA_DEFAULT_ENDPOINT, MAX_ENGINES,
};

pub const SEARCH_ENV: &str = "CITRATE_HERMES_SEARCH";
pub const SEARXNG_ENV: &str = "CITRATE_HERMES_SEARXNG";
pub const SEARXNG_DATA_ENV: &str = "CITRATE_HERMES_SEARXNG_DATA";
pub const SEARXNG_ENGINES_ENV: &str = "CITRATE_HERMES_SEARXNG_ENGINES";
pub const READER_ENV: &str = "CITRATE_HERMES_READER";
pub const JINA_ENDPOINT_ENV: &str = "CITRATE_HERMES_JINA_ENDPOINT";
pub const JINA_KEY_FILE_ENV: &str = "CITRATE_HERMES_JINA_KEY_FILE";

fn abs(v: Option<String>) -> Option<PathBuf> {
    v.filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// The engines named in a comma-separated list. Names SearXNG could not use are left out with a
/// note; an empty list means no engine at all.
fn engines_from(list: &str, notes: &mut Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        if !engine_name_ok(name) {
            notes.push(format!(
                "{SEARXNG_ENGINES_ENV}: an engine name was not usable and is left out"
            ));
        } else if out.len() >= MAX_ENGINES {
            notes.push(format!(
                "{SEARXNG_ENGINES_ENV}: more than {MAX_ENGINES} engines; the rest are left out"
            ));
            break;
        } else if !out.iter().any(|e| e == name) {
            out.push(name.to_string());
        }
    }
    if out.is_empty() {
        notes.push("SearXNG has no engine enabled; web_search will return no results".into());
    }
    out
}

/// The search configuration named by the environment, or `None` when search is off.
/// `notes` collects operator-facing lines (never a key).
pub fn search_config_from_vars(
    get: impl Fn(&str) -> Option<String>,
    notes: &mut Vec<String>,
) -> Option<SearchConfig> {
    if get(SEARCH_ENV).as_deref() != Some("1") {
        return None;
    }
    let searxng = match abs(get(SEARXNG_ENV)) {
        Some(program) => {
            let data = abs(get(SEARXNG_DATA_ENV)).unwrap_or_else(|| {
                std::env::temp_dir().join(format!("citrate-hermes-searxng-{}", std::process::id()))
            });
            let mut cfg = SearxngConfig::new(program, data);
            if let Some(list) = get(SEARXNG_ENGINES_ENV) {
                cfg.engines = engines_from(&list, notes);
            }
            Some(cfg)
        }
        None => {
            if get(SEARXNG_ENV).is_some() {
                notes.push(format!(
                    "{SEARXNG_ENV} is not an absolute path; web_search will report not installed"
                ));
            }
            None
        }
    };
    let reader = if get(READER_ENV).as_deref().map(str::trim) == Some("jina") {
        let endpoint = get(JINA_ENDPOINT_ENV)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| JINA_DEFAULT_ENDPOINT.to_string());
        let api_key = match abs(get(JINA_KEY_FILE_ENV)) {
            Some(p) => match std::fs::read_to_string(&p) {
                Ok(k) if !k.trim().is_empty() => Some(k.trim().to_string()),
                _ => {
                    notes.push(
                        "the Jina key file could not be read; the reader is used without a key"
                            .into(),
                    );
                    None
                }
            },
            None => None,
        };
        notes.push("read_url uses the Jina Reader (third-party, opted in)".into());
        ReaderBackend::Jina(JinaReader { endpoint, api_key })
    } else {
        ReaderBackend::Local
    };
    Some(SearchConfig {
        searxng,
        reader,
        ..SearchConfig::default()
    })
}

/// The search host when `CITRATE_HERMES_SEARCH=1` (default off -> `None`).
pub fn search_from_env() -> Option<Arc<SearchHost>> {
    let mut notes = Vec::new();
    let cfg = search_config_from_vars(|k| std::env::var(k).ok(), &mut notes)?;
    eprintln!(
        "citrate-agent-sidecar: web_search + read_url on; SearXNG {}",
        if cfg.searxng.is_some() {
            "configured (starts on first search)"
        } else {
            "not installed"
        }
    );
    for n in notes {
        eprintln!("citrate-agent-sidecar: {n}");
    }
    Some(Arc::new(SearchHost::new(cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn off_unless_exactly_one() {
        let mut n = vec![];
        assert!(search_config_from_vars(vars(&[]), &mut n).is_none());
        assert!(search_config_from_vars(vars(&[(SEARCH_ENV, "true")]), &mut n).is_none());
        assert!(search_config_from_vars(vars(&[(SEARCH_ENV, "1")]), &mut n).is_some());
    }

    #[test]
    fn defaults_are_local_reading_and_no_searxng() {
        let mut n = vec![];
        let c = search_config_from_vars(vars(&[(SEARCH_ENV, "1")]), &mut n).unwrap();
        assert!(c.searxng.is_none());
        assert_eq!(c.reader, ReaderBackend::Local);
        assert!(c.read.allow_private.is_empty());
    }

    #[test]
    fn searxng_path_must_be_absolute() {
        let mut n = vec![];
        let c = search_config_from_vars(
            vars(&[(SEARCH_ENV, "1"), (SEARXNG_ENV, "searxng-run")]),
            &mut n,
        )
        .unwrap();
        assert!(c.searxng.is_none());
        assert!(n.iter().any(|l| l.contains("not an absolute path")));
        let c = search_config_from_vars(
            vars(&[
                (SEARCH_ENV, "1"),
                (SEARXNG_ENV, "/opt/searxng/bin/searxng-run"),
                (SEARXNG_DATA_ENV, "/tmp/sx"),
            ]),
            &mut n,
        )
        .unwrap();
        let s = c.searxng.unwrap();
        assert_eq!(s.program, PathBuf::from("/opt/searxng/bin/searxng-run"));
        assert_eq!(s.data_dir, PathBuf::from("/tmp/sx"));
        assert_eq!(
            s.engines,
            citrate_agent_search::DEFAULT_ENGINES
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>(),
            "unset = the default list"
        );
    }

    #[test]
    fn the_engine_list_is_the_members_choice_and_names_are_checked() {
        let base = [
            (SEARCH_ENV, "1"),
            (SEARXNG_ENV, "/opt/searxng/bin/searxng-run"),
        ];
        let with = |list: &str, n: &mut Vec<String>| {
            let mut v = base.to_vec();
            v.push((SEARXNG_ENGINES_ENV, list));
            search_config_from_vars(vars(&v), n)
                .unwrap()
                .searxng
                .unwrap()
                .engines
        };
        let mut n = vec![];
        assert_eq!(
            with(" wikipedia , mojeek,wikipedia", &mut n),
            vec!["wikipedia", "mojeek"]
        );
        assert!(n.is_empty(), "{n:?}");
        let mut n = vec![];
        assert!(with("", &mut n).is_empty(), "empty = no engine at all");
        assert!(n.iter().any(|l| l.contains("no engine enabled")), "{n:?}");
        let mut n = vec![];
        assert_eq!(with("wikipedia,Bad\"Name,x:y", &mut n), vec!["wikipedia"]);
        assert!(n.iter().any(|l| l.contains("not usable")), "{n:?}");
        assert!(
            n.iter().all(|l| !l.contains("Bad")),
            "names are not echoed: {n:?}"
        );
        let many: Vec<String> = (0..40).map(|i| format!("e{i}")).collect();
        let mut n = vec![];
        assert_eq!(with(&many.join(","), &mut n).len(), MAX_ENGINES);
    }

    #[test]
    fn jina_is_an_explicit_opt_in_with_an_optional_key_file() {
        let dir = std::env::temp_dir().join(format!("n4-jina-key-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let key = dir.join("key");
        std::fs::write(&key, "  secret-key \n").unwrap();
        let mut n = vec![];
        let c = search_config_from_vars(
            vars(&[
                (SEARCH_ENV, "1"),
                (READER_ENV, "jina"),
                (JINA_KEY_FILE_ENV, key.to_str().unwrap()),
            ]),
            &mut n,
        )
        .unwrap();
        let ReaderBackend::Jina(j) = c.reader else {
            panic!("expected jina");
        };
        assert_eq!(j.endpoint, JINA_DEFAULT_ENDPOINT);
        assert_eq!(j.api_key.as_deref(), Some("secret-key"));
        assert!(n.iter().all(|l| !l.contains("secret-key")));
        let c = search_config_from_vars(vars(&[(SEARCH_ENV, "1"), (READER_ENV, "JINA ")]), &mut n)
            .unwrap();
        assert_eq!(
            c.reader,
            ReaderBackend::Local,
            "only the exact value opts in"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
