//! USB / removable-media carrier bundles (`.ddcarrier` directory or `.ddrop` archive).
//! Never includes private identity keys.

use crate::protocol::{decode_cbor, encode_cbor};
use crate::store::Store;
use crate::{DdError, PeerId, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarrierManifest {
    pub protocol: String,
    pub objects: u32,
    pub note: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportFilter {
    pub destination: Option<PeerId>,
    pub pending_only: bool,
}

/// Export envelopes, manifests, and present chunks. Identity keys MUST NOT be copied.
pub fn export_carrier(store: &Store, dest: &Path) -> Result<CarrierManifest> {
    export_carrier_filtered(store, dest, ExportFilter::default())
}

pub fn export_carrier_filtered(
    store: &Store,
    dest: &Path,
    filter: ExportFilter,
) -> Result<CarrierManifest> {
    fs::create_dir_all(dest.join("objects"))?;
    fs::create_dir_all(dest.join("manifests"))?;
    fs::create_dir_all(dest.join("chunks"))?;
    let now = crate::store::unix_now();
    let ids = store.inventory(now)?;
    let mut n = 0u32;
    for id in &ids {
        let Some(env) = store.get_envelope(id)? else {
            continue;
        };
        if let Some(dest_peer) = filter.destination
            && !env.destination.includes(&dest_peer)
            && !env.destination.is_public()
        {
            continue;
        }
        if filter.pending_only {
            let traces = store.traces(id).unwrap_or_default();
            let forwarded = traces.iter().any(|(_, e)| e.contains("forward"));
            if forwarded {
                continue;
            }
        }
        fs::write(
            dest.join("objects").join(format!("{id}.cbor")),
            encode_cbor(&env)?,
        )?;
        if let Some(man) = store.get_manifest(id)? {
            fs::write(
                dest.join("manifests").join(format!("{id}.cbor")),
                encode_cbor(&man)?,
            )?;
            let mask = store.present_mask(id)?;
            for (i, refer) in man.chunks.iter().enumerate() {
                if mask.get(i) == Some(&true)
                    && let Ok(data) = store.load_chunk(id, i as u32)
                {
                    let name = crate::hex_encode(refer.id.as_bytes());
                    fs::write(dest.join("chunks").join(name), data)?;
                }
            }
        }
        n += 1;
    }
    let man = CarrierManifest {
        protocol: crate::PROTOCOL_LABEL.into(),
        objects: n,
        note: "no private keys; physical sneakernet carrier".into(),
    };
    fs::write(
        dest.join("carrier.json"),
        serde_json::to_vec_pretty(&man).map_err(|e| DdError::crypto(e.to_string()))?,
    )?;
    Ok(man)
}

/// Single-file `.ddrop` archive (directory tree packed; no zip).
pub fn export_ddrop(store: &Store, dest: &Path, filter: ExportFilter) -> Result<CarrierManifest> {
    let tmp = dest.with_extension("ddrop-dir");
    let man = export_carrier_filtered(store, &tmp, filter)?;
    pack_ddrop(&tmp, dest)?;
    let _ = fs::remove_dir_all(&tmp);
    Ok(man)
}

pub fn pack_ddrop(dir: &Path, dest: &Path) -> Result<()> {
    let mut files = Vec::new();
    collect_files(dir, dir, &mut files)?;
    let mut out = fs::File::create(dest)?;
    out.write_all(b"DDROP1\n")?;
    out.write_all(&(files.len() as u32).to_be_bytes())?;
    for (name, data) in files {
        let nb = name.as_bytes();
        out.write_all(&(nb.len() as u16).to_be_bytes())?;
        out.write_all(nb)?;
        out.write_all(&(data.len() as u64).to_be_bytes())?;
        out.write_all(&data)?;
    }
    Ok(())
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) -> Result<()> {
    for ent in fs::read_dir(dir)? {
        let ent = ent?;
        let p = ent.path();
        if p.is_dir() {
            collect_files(root, &p, out)?;
        } else {
            let rel = p.strip_prefix(root).unwrap_or(&p);
            out.push((rel.to_string_lossy().replace('\\', "/"), fs::read(p)?));
        }
    }
    Ok(())
}

pub fn unpack_ddrop(src: &Path, dest: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    fs::File::open(src)?.read_to_end(&mut bytes)?;
    if bytes.len() < 11 || &bytes[..7] != b"DDROP1\n" {
        return Err(DdError::invalid_frame("not a .ddrop archive"));
    }
    let mut i = 7usize;
    let count = u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
    i += 4;
    fs::create_dir_all(dest)?;
    for _ in 0..count {
        if i + 2 > bytes.len() {
            return Err(DdError::invalid_frame("truncated ddrop"));
        }
        let nlen = u16::from_be_bytes(bytes[i..i + 2].try_into().unwrap()) as usize;
        i += 2;
        if i + nlen + 8 > bytes.len() {
            return Err(DdError::invalid_frame("truncated ddrop name"));
        }
        let name = std::str::from_utf8(&bytes[i..i + nlen])
            .map_err(|_| DdError::invalid_frame("ddrop name"))?;
        i += nlen;
        let dlen = u64::from_be_bytes(bytes[i..i + 8].try_into().unwrap()) as usize;
        i += 8;
        if i + dlen > bytes.len() {
            return Err(DdError::invalid_frame("truncated ddrop data"));
        }
        let data = &bytes[i..i + dlen];
        i += dlen;
        if name.contains("..") {
            return Err(DdError::invalid_frame("ddrop path"));
        }
        let path = dest.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, data)?;
    }
    Ok(())
}

/// Import a carrier directory or `.ddrop` file into the local store as relay content.
pub fn import_carrier(store: &Store, src: &Path) -> Result<u32> {
    let tmp_holder: Option<std::path::PathBuf>;
    let root = if src.is_file() {
        let tmp = src.with_extension("ddrop-unpack");
        unpack_ddrop(src, &tmp)?;
        tmp_holder = Some(tmp.clone());
        tmp
    } else {
        tmp_holder = None;
        src.to_path_buf()
    };
    let n = import_dir(store, &root)?;
    if let Some(t) = tmp_holder {
        let _ = fs::remove_dir_all(t);
    }
    Ok(n)
}

fn import_dir(store: &Store, src: &Path) -> Result<u32> {
    let obj_dir = src.join("objects");
    let mut n = 0u32;
    let now = crate::store::unix_now();
    let rd = match fs::read_dir(&obj_dir) {
        Ok(r) => r,
        Err(_) => return Ok(0),
    };
    for ent in rd.flatten() {
        let bytes = fs::read(ent.path())?;
        let env: crate::DropEnvelope = decode_cbor(&bytes)?;
        let man_path = src
            .join("manifests")
            .join(format!("{}.cbor", env.object_id));
        let man: crate::chunk::Manifest = if man_path.exists() {
            decode_cbor(&fs::read(&man_path)?)?
        } else {
            continue;
        };
        let mut chunks = Vec::new();
        for (i, refer) in man.chunks.iter().enumerate() {
            let p = src
                .join("chunks")
                .join(crate::hex_encode(refer.id.as_bytes()));
            if p.exists() {
                chunks.push((i as u32, fs::read(p)?));
            }
        }
        let _ = store.put_object(&env, &man, &chunks, crate::Ownership::Relay, now);
        n += 1;
    }
    Ok(n)
}
