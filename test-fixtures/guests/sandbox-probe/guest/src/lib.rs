//! HUP-S2.5 sandbox probe guest. Each call performs exactly one operation
//! through the guest's own WASI imports (wasi-libc over wasi:filesystem and
//! wasi:sockets), so the host decides with the same checks a real capsule
//! meets. Test fixture only.

wit_bindgen::generate!({
    world: "sandbox-probe",
    path: "../wit",
});

use std::io::{Read, Write};

struct Probe;

fn kind(e: &std::io::Error) -> String {
    format!("err:{:?}", e.kind())
}

impl exports::citrate::sandbox_probe::probe::Guest for Probe {
    fn run(op: String, target: String) -> String {
        match op.as_str() {
            "read" => match std::fs::File::open(&target) {
                Ok(mut f) => {
                    let mut s = String::new();
                    match f.read_to_string(&mut s) {
                        Ok(_) => format!("ok:{s}"),
                        Err(e) => kind(&e),
                    }
                }
                Err(e) => kind(&e),
            },
            "write" => match std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&target)
            {
                Ok(mut f) => match f.write_all(b"written by a capsule") {
                    Ok(()) => "ok:written".to_string(),
                    Err(e) => kind(&e),
                },
                Err(e) => kind(&e),
            },
            "list" => match std::fs::read_dir(&target) {
                Ok(rd) => {
                    let mut names: Vec<String> = rd
                        .filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    names.sort();
                    format!("ok:{}", names.join(","))
                }
                Err(e) => kind(&e),
            },
            "connect" => match target.parse::<std::net::SocketAddr>() {
                Ok(addr) => match std::net::TcpStream::connect(addr) {
                    Ok(_) => "ok:connected".to_string(),
                    Err(e) => kind(&e),
                },
                Err(_) => "err:BadAddress".to_string(),
            },
            _ => "err:UnknownOp".to_string(),
        }
    }
}

export!(Probe);
