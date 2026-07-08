//! Minimal HTTP static server for bare c14 outboard artifacts with HTTP Range support.
//!
//! Demonstrates verified slice reads via [`carbonado::verify_slice_outboard`] for
//! partial content (206) responses.

use std::env;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use carbonado::paths::sidecar_sibling_path;
use carbonado::verify_slice_outboard;
use positioned_io::ReadAt;
use tiny_http::{Header, Method, Response, Server, StatusCode};

type HttpResponse = Response<Cursor<Vec<u8>>>;

struct ArtifactSet {
    main_path: PathBuf,
    bao_outboard: Option<Vec<u8>>,
    _fec_parity: Option<Vec<u8>>,
    bao_root: [u8; 32],
    bao_root_hex: String,
    format: u8,
}

struct MainReadAt(File);

impl ReadAt for MainReadAt {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut f = &self.0;
        f.seek(SeekFrom::Start(offset))?;
        f.read(buf)
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let mut f = &self.0;
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(buf)
    }
}

fn parse_bao_root_hex(path: &Path) -> Result<String, String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "artifact path has no filename".to_string())?;
    let stem = name
        .strip_suffix(".adam.c14")
        .or_else(|| name.strip_suffix(".c14"))
        .or_else(|| {
            name.rsplit_once('.').and_then(|(s, ext)| {
                if ext.len() == 3
                    && ext.starts_with('c')
                    && ext[1..].chars().all(|c| c.is_ascii_hexdigit())
                {
                    Some(s)
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| format!("cannot parse bao root from filename: {name}"))?;
    if stem.len() != 64 || !stem.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("expected 64-hex bao root in filename, got: {stem}"));
    }
    Ok(stem.to_ascii_lowercase())
}

fn parse_root_bytes(hex: &str) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    for (i, c) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(c).map_err(|e| e.to_string())?;
        out[i] = u8::from_str_radix(s, 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn load_artifacts(main_path: &Path) -> Result<ArtifactSet, Box<dyn std::error::Error>> {
    let bao_root_hex = parse_bao_root_hex(main_path)?;
    let bao_root = parse_root_bytes(&bao_root_hex)?;
    let format = carbonado::paths::guess_format_from_filename(main_path).unwrap_or(0x0E);
    let out_path = sidecar_sibling_path(main_path, "out");
    let par_path = sidecar_sibling_path(main_path, "par");
    let bao_outboard = if out_path.is_file() {
        Some(std::fs::read(out_path)?)
    } else {
        None
    };
    let fec_parity = if par_path.is_file() {
        Some(std::fs::read(par_path)?)
    } else {
        None
    };
    Ok(ArtifactSet {
        main_path: main_path.to_path_buf(),
        bao_outboard,
        _fec_parity: fec_parity,
        bao_root,
        bao_root_hex,
        format,
    })
}

fn octet_stream() -> Header {
    Header::from_bytes(b"Content-Type", b"application/octet-stream").expect("header")
}

fn parse_range_header(value: &str, total: u64) -> Option<(u64, u64)> {
    let v = value.strip_prefix("bytes=")?;
    let (start_s, end_s) = v.split_once('-')?;
    let start: u64 = start_s.parse().ok()?;
    let end = if end_s.is_empty() {
        total.saturating_sub(1)
    } else {
        end_s.parse().ok()?
    };
    if start > end || end >= total {
        return None;
    }
    Some((start, end))
}

fn serve_range(artifacts: &ArtifactSet, start: u64, end: u64) -> Result<HttpResponse, String> {
    let count_slices = ((end + 1 - start) as u32).div_ceil(4096).max(1);
    let index = (start / 4096) as u32;
    let main = MainReadAt(File::open(&artifacts.main_path).map_err(|e| e.to_string())?);
    let ob = artifacts
        .bao_outboard
        .as_deref()
        .ok_or_else(|| "range requests require bao outboard sidecar".to_string())?;
    let verified = verify_slice_outboard(
        &main,
        ob,
        artifacts.main_len(),
        index,
        count_slices,
        &artifacts.bao_root,
        artifacts.format,
    )
    .map_err(|e| e.to_string())?;
    let slice_start = (start % 4096) as usize;
    let want = (end - start + 1) as usize;
    let body = verified
        .get(slice_start..slice_start + want)
        .ok_or_else(|| "range exceeds verified slice".to_string())?
        .to_vec();
    let mut resp = Response::from_data(body)
        .with_status_code(StatusCode(206))
        .with_header(octet_stream());
    let range = format!("bytes {start}-{end}/{}", artifacts.main_len());
    resp.add_header(Header::from_bytes(b"Content-Range", range.as_bytes()).unwrap());
    Ok(resp)
}

trait MainLen {
    fn main_len(&self) -> u64;
}

impl MainLen for ArtifactSet {
    fn main_len(&self) -> u64 {
        std::fs::metadata(&self.main_path)
            .map(|m| m.len())
            .unwrap_or(0)
    }
}

fn serve_bytes(body: &[u8]) -> HttpResponse {
    Response::from_data(body.to_vec())
        .with_status_code(StatusCode(200))
        .with_header(octet_stream())
}

fn not_found(msg: &str) -> HttpResponse {
    Response::from_string(msg).with_status_code(StatusCode(404))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let main_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: bare_serve <path-to.c14>")?;
    if !main_path.is_file() {
        return Err(format!("not a file: {}", main_path.display()).into());
    }

    let artifacts = load_artifacts(&main_path)?;
    let port: u16 = env::var("CARBONADO_SERVE_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let bind = env::var("CARBONADO_SERVE_BIND").unwrap_or_else(|_| "127.0.0.1".into());

    let server = Server::http(format!("{bind}:{port}")).map_err(|e| e.to_string())?;
    let total = artifacts.main_len();
    println!(
        "serving {} (bao root {}) on http://{bind}:{port}/",
        main_path.display(),
        artifacts.bao_root_hex
    );
    println!("  GET /file.c14  ({total} bytes, Range supported when .out sidecar present)");

    for request in server.incoming_requests() {
        if request.method() != &Method::Get {
            let _ = request.respond(not_found("GET only"));
            continue;
        }
        let response = if request.url() != "/file.c14" {
            not_found("not found; use /file.c14")
        } else if let Some(range) = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Range"))
            .map(|h| h.value.as_str())
            .and_then(|v| parse_range_header(v, total))
        {
            match serve_range(&artifacts, range.0, range.1) {
                Ok(r) => r,
                Err(e) => not_found(&e),
            }
        } else {
            match std::fs::read(&artifacts.main_path) {
                Ok(b) => serve_bytes(&b),
                Err(e) => not_found(&e.to_string()),
            }
        };
        let _ = request.respond(response);
    }
    Ok(())
}
