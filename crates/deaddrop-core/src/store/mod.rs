use crate::chunk::{Manifest, verify_chunk};
use crate::crypto::{CryptoProvider, DefaultProvider, PrivateIdentity};
use crate::identity::{Contact, ContactBook, ContactCard, IdentityFile};
use crate::protocol::{decode_cbor, encode_cbor, verify_envelope};
use crate::{
    DEFAULT_STORE_QUOTA, DdError, DropEnvelope, DropState, ErrorCode, ObjectId, Ownership, PeerId,
    Result, STORAGE_SCHEMA_VERSION, TrustState, hex_encode,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct StorageQuotas {
    pub maximum: u64,
    pub reserved_local: u64,
    pub relay_budget: u64,
    pub temporary: u64,
}

impl Default for StorageQuotas {
    fn default() -> Self {
        Self {
            maximum: DEFAULT_STORE_QUOTA,
            reserved_local: 5 * 1024 * 1024 * 1024,
            relay_budget: 10 * 1024 * 1024 * 1024,
            temporary: 5 * 1024 * 1024 * 1024,
        }
    }
}

pub struct Store {
    root: PathBuf,
    quotas: StorageQuotas,
    db: Mutex<Connection>,
}

impl Store {
    pub fn open(root: impl AsRef<Path>, quotas: StorageQuotas) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("chunks"))?;
        fs::create_dir_all(root.join("objects"))?;
        fs::create_dir_all(root.join("manifests"))?;
        fs::create_dir_all(root.join("identities"))?;
        let db_path = root.join("meta.sqlite");
        let db = Connection::open(&db_path).map_err(sql_err)?;
        db.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS objects (
                object_id BLOB PRIMARY KEY,
                envelope BLOB NOT NULL,
                source BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                priority INTEGER NOT NULL,
                hop_count INTEGER NOT NULL,
                hop_limit INTEGER NOT NULL,
                state TEXT NOT NULL,
                ownership TEXT NOT NULL,
                size INTEGER NOT NULL,
                replication INTEGER NOT NULL,
                application TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chunks (
                content_id BLOB PRIMARY KEY,
                size INTEGER NOT NULL,
                refcount INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS object_chunks (
                object_id BLOB NOT NULL,
                idx INTEGER NOT NULL,
                content_id BLOB NOT NULL,
                present INTEGER NOT NULL,
                PRIMARY KEY (object_id, idx)
            );
            CREATE TABLE IF NOT EXISTS manifests (
                manifest_id BLOB PRIMARY KEY,
                object_id BLOB NOT NULL,
                body BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS contacts (
                peer_id BLOB PRIMARY KEY,
                card TEXT NOT NULL,
                trust TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS encounters (
                peer_id BLOB PRIMARY KEY,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                encounter_count INTEGER NOT NULL,
                bytes_sent INTEGER NOT NULL,
                bytes_received INTEGER NOT NULL,
                successful_forwards INTEGER NOT NULL,
                failed_forwards INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id BLOB PRIMARY KEY,
                object_id BLOB NOT NULL,
                kind TEXT NOT NULL,
                body BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS traces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                object_id BLOB NOT NULL,
                ts INTEGER NOT NULL,
                event TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pins (
                object_id BLOB PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS tags (
                object_id BLOB NOT NULL,
                tag TEXT NOT NULL,
                PRIMARY KEY (object_id, tag)
            );
            CREATE TABLE IF NOT EXISTS aliases (
                peer_id BLOB PRIMARY KEY,
                alias TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS spaces (
                name TEXT PRIMARY KEY,
                body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS channels (
                name TEXT PRIMARY KEY,
                filter TEXT NOT NULL,
                policy TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS circles (
                name TEXT PRIMARY KEY,
                members TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS kv (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_objects_exp ON objects(expires_at);
            ",
        )
        .map_err(sql_err)?;
        db.execute(
            "INSERT OR IGNORE INTO meta(k,v) VALUES('schema', ?1)",
            params![STORAGE_SCHEMA_VERSION.to_string()],
        )
        .map_err(sql_err)?;
        Ok(Self {
            root,
            quotas,
            db: Mutex::new(db),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn identity_path(&self) -> PathBuf {
        self.root.join("identities").join("identity.json")
    }

    pub fn save_identity(&self, id: &PrivateIdentity) -> Result<()> {
        let file = IdentityFile::from_private(id);
        fs::write(
            self.identity_path(),
            serde_json::to_vec_pretty(&file).map_err(|e| DdError::crypto(e.to_string()))?,
        )?;
        Ok(())
    }

    pub fn load_identity(&self) -> Result<PrivateIdentity> {
        let bytes = fs::read(self.identity_path())?;
        let file: IdentityFile =
            serde_json::from_slice(&bytes).map_err(|e| DdError::crypto(e.to_string()))?;
        file.into_private()
    }

    pub fn init_identity(&self, force: bool) -> Result<PrivateIdentity> {
        if self.identity_path().exists() && !force {
            return Err(DdError::protocol(
                ErrorCode::Ddx0000Internal,
                "identity exists (use rotate, not silent replace)",
            ));
        }
        let id = PrivateIdentity::generate();
        self.save_identity(&id)?;
        Ok(id)
    }

    pub fn put_contact(&self, card: ContactCard, trust: TrustState) -> Result<PeerId> {
        let id = card.peer_id()?;
        let json = card.to_ddcontact()?;
        self.db
            .lock()
            .expect("db")
            .execute(
                "INSERT OR REPLACE INTO contacts(peer_id, card, trust) VALUES(?1,?2,?3)",
                params![
                    id.as_bytes().as_slice(),
                    json,
                    format!("{trust:?}").to_lowercase()
                ],
            )
            .map_err(sql_err)?;
        Ok(id)
    }

    pub fn load_contacts(&self) -> Result<ContactBook> {
        let db = self.db.lock().expect("db");
        let mut stmt = db
            .prepare("SELECT card, trust FROM contacts")
            .map_err(sql_err)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sql_err)?;
        let mut book = ContactBook::default();
        for row in rows {
            let (card_s, trust_s) = row.map_err(sql_err)?;
            if let Ok(card) = ContactCard::from_bytes(card_s.as_bytes()) {
                let trust = parse_trust(&trust_s);
                let _ = book.insert(Contact { card, trust });
            }
        }
        drop(stmt);
        let mut astmt = db
            .prepare("SELECT peer_id, alias FROM aliases")
            .map_err(sql_err)?;
        let arows = astmt
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sql_err)?;
        for row in arows {
            let (pid, alias) = row.map_err(sql_err)?;
            if pid.len() == 32 {
                let mut d = [0u8; 32];
                d.copy_from_slice(&pid);
                let id = PeerId::from_digest(d);
                if let Some(c) = book.get_mut(&id) {
                    c.card.name = Some(alias);
                }
            }
        }
        Ok(book)
    }

    pub fn put_object(
        &self,
        env: &DropEnvelope,
        manifest: &Manifest,
        chunks: &[(u32, Vec<u8>)],
        ownership: Ownership,
        now: u64,
    ) -> Result<ObjectId> {
        verify_envelope(env, now)?;
        let used = self.physical_bytes()?;
        let incoming: u64 = chunks.iter().map(|(_, d)| d.len() as u64).sum();
        if used.saturating_add(incoming) > self.quotas.maximum {
            return Err(DdError::protocol(ErrorCode::Dds2001StoreFull, "quota"));
        }
        let env_bytes = encode_cbor(env)?;
        let man_bytes = encode_cbor(manifest)?;
        let oid = env.object_id;
        {
            let db = self.db.lock().expect("db");
            db.execute(
                "INSERT OR REPLACE INTO objects(object_id,envelope,source,created_at,expires_at,priority,hop_count,hop_limit,state,ownership,size,replication,application)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    oid.as_bytes().as_slice(),
                    env_bytes,
                    env.source.as_bytes().as_slice(),
                    env.creation_time as i64,
                    env.expiration as i64,
                    env.priority.as_u8() as i64,
                    env.hop_count as i64,
                    env.hop_limit as i64,
                    "stored",
                    ownership_str(ownership),
                    manifest.total_length as i64,
                    env.routing_policy.replication_budget as i64,
                    env.application,
                ],
            )
            .map_err(sql_err)?;
            db.execute(
                "INSERT OR REPLACE INTO manifests(manifest_id, object_id, body) VALUES(?1,?2,?3)",
                params![
                    manifest.id().as_bytes().as_slice(),
                    oid.as_bytes().as_slice(),
                    man_bytes
                ],
            )
            .map_err(sql_err)?;
        }
        for (idx, refer) in manifest.chunks.iter().enumerate() {
            self.db
                .lock()
                .expect("db")
                .execute(
                    "INSERT OR REPLACE INTO object_chunks(object_id, idx, content_id, present) VALUES(?1,?2,?3,0)",
                    params![
                        oid.as_bytes().as_slice(),
                        idx as i64,
                        refer.id.as_bytes().as_slice()
                    ],
                )
                .map_err(sql_err)?;
        }
        for (idx, data) in chunks {
            self.put_chunk(oid, *idx, data)?;
        }
        self.trace(oid, now, "stored")?;
        Ok(oid)
    }

    pub fn put_chunk(&self, object_id: ObjectId, index: u32, data: &[u8]) -> Result<()> {
        let refer = self.chunk_ref(object_id, index)?;
        verify_chunk(&refer, data)?;
        let path = self.chunk_path(&refer);
        if !path.exists() {
            fs::write(&path, data)?;
            self.db
                .lock()
                .expect("db")
                .execute(
                    "INSERT INTO chunks(content_id,size,refcount) VALUES(?1,?2,1)
                     ON CONFLICT(content_id) DO UPDATE SET refcount = refcount + 1",
                    params![refer.as_bytes().as_slice(), data.len() as i64],
                )
                .map_err(sql_err)?;
        }
        self.db
            .lock()
            .expect("db")
            .execute(
                "UPDATE object_chunks SET present=1 WHERE object_id=?1 AND idx=?2",
                params![object_id.as_bytes().as_slice(), index as i64],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn chunk_ref(&self, object_id: ObjectId, index: u32) -> Result<crate::ChunkId> {
        let db = self.db.lock().expect("db");
        let bytes: Vec<u8> = db
            .query_row(
                "SELECT content_id FROM object_chunks WHERE object_id=?1 AND idx=?2",
                params![object_id.as_bytes().as_slice(), index as i64],
                |r| r.get(0),
            )
            .map_err(|_| DdError::protocol(ErrorCode::Dds2003MissingChunk, "index"))?;
        if bytes.len() != 32 {
            return Err(DdError::protocol(
                ErrorCode::Dds2004CorruptMetadata,
                "chunk id",
            ));
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(&bytes);
        Ok(crate::ChunkId::blake3(d))
    }

    fn chunk_path(&self, id: &crate::ChunkId) -> PathBuf {
        self.root.join("chunks").join(hex_encode(id.as_bytes()))
    }

    pub fn get_envelope(&self, id: &ObjectId) -> Result<Option<DropEnvelope>> {
        let db = self.db.lock().expect("db");
        let blob: Option<Vec<u8>> = db
            .query_row(
                "SELECT envelope FROM objects WHERE object_id=?1",
                params![id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql_err)?;
        blob.map(|b| decode_cbor(&b)).transpose()
    }

    pub fn get_manifest(&self, id: &ObjectId) -> Result<Option<Manifest>> {
        let db = self.db.lock().expect("db");
        let blob: Option<Vec<u8>> = db
            .query_row(
                "SELECT body FROM manifests WHERE object_id=?1",
                params![id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql_err)?;
        blob.map(|b| decode_cbor(&b)).transpose()
    }

    pub fn present_mask(&self, id: &ObjectId) -> Result<Vec<bool>> {
        let db = self.db.lock().expect("db");
        let mut stmt = db
            .prepare("SELECT idx, present FROM object_chunks WHERE object_id=?1 ORDER BY idx")
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![id.as_bytes().as_slice()], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            })
            .map_err(sql_err)?;
        let mut mask = Vec::new();
        for row in rows {
            let (idx, p) = row.map_err(sql_err)?;
            let i = idx as usize;
            if mask.len() <= i {
                mask.resize(i + 1, false);
            }
            mask[i] = p != 0;
        }
        Ok(mask)
    }

    pub fn load_chunks(&self, id: &ObjectId) -> Result<Vec<Vec<u8>>> {
        let man = self
            .get_manifest(id)?
            .ok_or_else(|| DdError::protocol(ErrorCode::Dds2003MissingChunk, "manifest"))?;
        let slots = self.load_chunk_slots(id)?;
        if man.erasure.is_some() {
            return crate::chunk::reconstruct(&man, &slots);
        }
        let mut out = Vec::new();
        for (i, refer) in man.chunks.iter().enumerate() {
            let data = slots.get(i).and_then(|s| s.as_ref()).ok_or_else(|| {
                DdError::protocol(ErrorCode::Dds2003MissingChunk, format!("chunk {i}"))
            })?;
            verify_chunk(&refer.id, data)?;
            out.push(data.clone());
        }
        Ok(out)
    }

    pub fn load_chunk(&self, id: &ObjectId, index: u32) -> Result<Vec<u8>> {
        let refer = self.chunk_ref(*id, index)?;
        let data = fs::read(self.chunk_path(&refer))?;
        verify_chunk(&refer, &data)?;
        Ok(data)
    }

    pub fn inventory(&self, now: u64) -> Result<Vec<ObjectId>> {
        let db = self.db.lock().expect("db");
        let mut stmt = db
            .prepare("SELECT object_id FROM objects WHERE expires_at > ?1 AND state != 'garbagecollected'")
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![now as i64], |r| r.get::<_, Vec<u8>>(0))
            .map_err(sql_err)?;
        let mut ids = Vec::new();
        for row in rows {
            let b = row.map_err(sql_err)?;
            if b.len() == 32 {
                let mut d = [0u8; 32];
                d.copy_from_slice(&b);
                ids.push(ObjectId::blake3(d));
            }
        }
        ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        Ok(ids)
    }

    pub fn complete(&self, id: &ObjectId) -> Result<bool> {
        let Some(man) = self.get_manifest(id)? else {
            return Ok(false);
        };
        let mask = self.present_mask(id)?;
        Ok(crate::chunk::can_recover(&man, &mask))
    }

    pub fn load_chunk_slots(&self, id: &ObjectId) -> Result<Vec<Option<Vec<u8>>>> {
        let man = self
            .get_manifest(id)?
            .ok_or_else(|| DdError::protocol(ErrorCode::Dds2003MissingChunk, "manifest"))?;
        let mut out = Vec::with_capacity(man.chunks.len());
        for refer in &man.chunks {
            let path = self.chunk_path(&refer.id);
            if path.exists() {
                let data = fs::read(&path)?;
                if crate::chunk::verify_chunk(&refer.id, &data).is_ok() {
                    out.push(Some(data));
                    continue;
                }
            }
            out.push(None);
        }
        Ok(out)
    }

    pub fn stats(&self) -> Result<StoreStats> {
        let db = self.db.lock().expect("db");
        let objects: i64 = db
            .query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))
            .map_err(sql_err)?;
        let chunks: i64 = db
            .query_row("SELECT COUNT(*) FROM chunks", [], |r| r.get(0))
            .map_err(sql_err)?;
        let logical: i64 = db
            .query_row("SELECT COALESCE(SUM(size),0) FROM objects", [], |r| {
                r.get(0)
            })
            .map_err(sql_err)?;
        let physical: i64 = db
            .query_row("SELECT COALESCE(SUM(size),0) FROM chunks", [], |r| r.get(0))
            .map_err(sql_err)?;
        drop(db);
        Ok(StoreStats {
            objects: objects as u64,
            payloads: objects as u64,
            chunks: chunks as u64,
            logical_size: logical as u64,
            physical_size: physical as u64,
        })
    }

    pub fn physical_bytes(&self) -> Result<u64> {
        Ok(self.stats()?.physical_size)
    }

    pub fn gc(&self, now: u64) -> Result<u32> {
        let db = self.db.lock().expect("db");
        let n = db
            .execute(
                "UPDATE objects SET state='expired' WHERE expires_at <= ?1 AND ownership != 'local' AND object_id NOT IN (SELECT object_id FROM pins)",
                params![now as i64],
            )
            .map_err(sql_err)?;
        let n2 = db
            .execute(
                "UPDATE objects SET state='garbagecollected' WHERE state='expired'",
                [],
            )
            .map_err(sql_err)?;
        Ok((n + n2) as u32)
    }

    pub fn verify(&self) -> Result<Vec<String>> {
        let mut problems = Vec::new();
        let ids = self.inventory(unix_now()).unwrap_or_default();
        for id in ids {
            if let Ok(Some(man)) = self.get_manifest(&id) {
                let mask = self.present_mask(&id)?;
                for (i, refer) in man.chunks.iter().enumerate() {
                    if mask.get(i) == Some(&true) {
                        let path = self.chunk_path(&refer.id);
                        match fs::read(&path) {
                            Ok(d) => {
                                if verify_chunk(&refer.id, &d).is_err() {
                                    problems.push(format!("corrupt chunk {i} of {id}"));
                                }
                            }
                            Err(_) => problems.push(format!("missing chunk file {i} of {id}")),
                        }
                    }
                }
            }
        }
        Ok(problems)
    }

    pub fn record_encounter(
        &self,
        peer: PeerId,
        now: u64,
        sent: u64,
        recv: u64,
        ok: bool,
    ) -> Result<()> {
        let db = self.db.lock().expect("db");
        db.execute(
            "INSERT INTO encounters(peer_id,first_seen,last_seen,encounter_count,bytes_sent,bytes_received,successful_forwards,failed_forwards)
             VALUES(?1,?2,?2,1,?3,?4,?5,?6)
             ON CONFLICT(peer_id) DO UPDATE SET
               last_seen=excluded.last_seen,
               encounter_count=encounter_count+1,
               bytes_sent=bytes_sent+excluded.bytes_sent,
               bytes_received=bytes_received+excluded.bytes_received,
               successful_forwards=successful_forwards+excluded.successful_forwards,
               failed_forwards=failed_forwards+excluded.failed_forwards",
            params![
                peer.as_bytes().as_slice(),
                now as i64,
                sent as i64,
                recv as i64,
                if ok { 1 } else { 0 },
                if ok { 0 } else { 1 }
            ],
        )
        .map_err(sql_err)?;
        drop(db);
        self.touch_hour_hist(peer, now)?;
        Ok(())
    }

    pub fn encounter(&self, peer: PeerId) -> Result<Option<EncounterRow>> {
        let db = self.db.lock().expect("db");
        db.query_row(
            "SELECT first_seen,last_seen,encounter_count,bytes_sent,bytes_received,successful_forwards,failed_forwards FROM encounters WHERE peer_id=?1",
            params![peer.as_bytes().as_slice()],
            |r| {
                Ok(EncounterRow {
                    first_seen: r.get::<_, i64>(0)? as u64,
                    last_seen: r.get::<_, i64>(1)? as u64,
                    encounter_count: r.get::<_, i64>(2)? as u64,
                    bytes_sent: r.get::<_, i64>(3)? as u64,
                    bytes_received: r.get::<_, i64>(4)? as u64,
                    successful_forwards: r.get::<_, i64>(5)? as u64,
                    failed_forwards: r.get::<_, i64>(6)? as u64,
                })
            },
        )
        .optional()
        .map_err(sql_err)
    }

    pub fn all_encounters(&self) -> Result<Vec<(PeerId, EncounterRow)>> {
        let db = self.db.lock().expect("db");
        let mut stmt = db
            .prepare("SELECT peer_id,first_seen,last_seen,encounter_count,bytes_sent,bytes_received,successful_forwards,failed_forwards FROM encounters")
            .map_err(sql_err)?;
        let rows = stmt
            .query_map([], |r| {
                let b: Vec<u8> = r.get(0)?;
                Ok((
                    b,
                    EncounterRow {
                        first_seen: r.get::<_, i64>(1)? as u64,
                        last_seen: r.get::<_, i64>(2)? as u64,
                        encounter_count: r.get::<_, i64>(3)? as u64,
                        bytes_sent: r.get::<_, i64>(4)? as u64,
                        bytes_received: r.get::<_, i64>(5)? as u64,
                        successful_forwards: r.get::<_, i64>(6)? as u64,
                        failed_forwards: r.get::<_, i64>(7)? as u64,
                    },
                ))
            })
            .map_err(sql_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (b, e) = row.map_err(sql_err)?;
            if b.len() == 32 {
                let mut d = [0u8; 32];
                d.copy_from_slice(&b);
                out.push((PeerId::from_digest(d), e));
            }
        }
        Ok(out)
    }

    pub fn set_state(&self, id: &ObjectId, state: DropState) -> Result<()> {
        self.db
            .lock()
            .expect("db")
            .execute(
                "UPDATE objects SET state=?1 WHERE object_id=?2",
                params![
                    format!("{state:?}").to_lowercase(),
                    id.as_bytes().as_slice()
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn decrement_replication(&self, id: &ObjectId) -> Result<u32> {
        let db = self.db.lock().expect("db");
        db.execute(
            "UPDATE objects SET replication = MAX(replication-1,0) WHERE object_id=?1",
            params![id.as_bytes().as_slice()],
        )
        .map_err(sql_err)?;
        let v: i64 = db
            .query_row(
                "SELECT replication FROM objects WHERE object_id=?1",
                params![id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .map_err(sql_err)?;
        Ok(v as u32)
    }

    pub fn replication(&self, id: &ObjectId) -> Result<u32> {
        let v: i64 = self
            .db
            .lock()
            .expect("db")
            .query_row(
                "SELECT replication FROM objects WHERE object_id=?1",
                params![id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .map_err(sql_err)?;
        Ok(v as u32)
    }

    pub fn ownership(&self, id: &ObjectId) -> Result<Ownership> {
        let s: String = self
            .db
            .lock()
            .expect("db")
            .query_row(
                "SELECT ownership FROM objects WHERE object_id=?1",
                params![id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .map_err(sql_err)?;
        Ok(parse_own(&s))
    }

    pub fn bump_hop(&self, env: &mut DropEnvelope) {
        env.hop_count = env.hop_count.saturating_add(1);
    }

    pub fn trace(&self, id: ObjectId, ts: u64, event: &str) -> Result<()> {
        self.db
            .lock()
            .expect("db")
            .execute(
                "INSERT INTO traces(object_id,ts,event) VALUES(?1,?2,?3)",
                params![id.as_bytes().as_slice(), ts as i64, event],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn traces(&self, id: &ObjectId) -> Result<Vec<(u64, String)>> {
        let db = self.db.lock().expect("db");
        let mut stmt = db
            .prepare("SELECT ts,event FROM traces WHERE object_id=?1 ORDER BY id")
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![id.as_bytes().as_slice()], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
            })
            .map_err(sql_err)?;
        let mut v = Vec::new();
        for row in rows {
            v.push(row.map_err(sql_err)?);
        }
        Ok(v)
    }

    pub fn pin(&self, id: &ObjectId) -> Result<()> {
        self.db
            .lock()
            .expect("db")
            .execute(
                "INSERT OR IGNORE INTO pins(object_id) VALUES(?1)",
                params![id.as_bytes().as_slice()],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn unpin(&self, id: &ObjectId) -> Result<()> {
        self.db
            .lock()
            .expect("db")
            .execute(
                "DELETE FROM pins WHERE object_id=?1",
                params![id.as_bytes().as_slice()],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn is_pinned(&self, id: &ObjectId) -> Result<bool> {
        let n: i64 = self
            .db
            .lock()
            .expect("db")
            .query_row(
                "SELECT COUNT(*) FROM pins WHERE object_id=?1",
                params![id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .map_err(sql_err)?;
        Ok(n > 0)
    }

    pub fn tag(&self, id: &ObjectId, tag: &str) -> Result<()> {
        self.db
            .lock()
            .expect("db")
            .execute(
                "INSERT OR IGNORE INTO tags(object_id, tag) VALUES(?1,?2)",
                params![id.as_bytes().as_slice(), tag],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn set_alias(&self, peer: PeerId, alias: &str) -> Result<()> {
        self.db
            .lock()
            .expect("db")
            .execute(
                "INSERT OR REPLACE INTO aliases(peer_id, alias) VALUES(?1,?2)",
                params![peer.as_bytes().as_slice(), alias],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn alias(&self, peer: PeerId) -> Result<Option<String>> {
        self.db
            .lock()
            .expect("db")
            .query_row(
                "SELECT alias FROM aliases WHERE peer_id=?1",
                params![peer.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql_err)
    }

    pub fn search_meta(&self, q: &str) -> Result<Vec<ObjectId>> {
        let needle = q.to_ascii_lowercase();
        let mut hits = Vec::new();
        for id in self.inventory(unix_now())? {
            let Some(env) = self.get_envelope(&id)? else {
                continue;
            };
            let blob = format!(
                "{} {} {:?} {}",
                env.application,
                env.source,
                env.destination,
                env.topic.as_deref().unwrap_or("")
            )
            .to_ascii_lowercase();
            if blob.contains(&needle) {
                hits.push(id);
            }
        }
        Ok(hits)
    }

    pub fn put_space(&self, rec: &crate::space::SpaceRecord) -> Result<()> {
        let body = serde_json::to_string(rec).map_err(|e| DdError::crypto(e.to_string()))?;
        self.db
            .lock()
            .expect("db")
            .execute(
                "INSERT OR REPLACE INTO spaces(name, body) VALUES(?1,?2)",
                params![rec.name, body],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn list_spaces(&self) -> Result<Vec<crate::space::SpaceRecord>> {
        let db = self.db.lock().expect("db");
        let mut stmt = db.prepare("SELECT body FROM spaces").map_err(sql_err)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(sql_err)?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(s) = serde_json::from_str(&row.map_err(sql_err)?) {
                out.push(s);
            }
        }
        Ok(out)
    }

    pub fn subscribe_channel(&self, sub: &crate::channel::ChannelSub) -> Result<()> {
        self.db
            .lock()
            .expect("db")
            .execute(
                "INSERT OR REPLACE INTO channels(name, filter, policy) VALUES(?1,?2,?3)",
                params![
                    sub.name,
                    format!("{:?}", sub.filter).to_lowercase(),
                    format!("{:?}", sub.policy).to_lowercase()
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn list_channels(&self) -> Result<Vec<(String, String, String)>> {
        let db = self.db.lock().expect("db");
        let mut stmt = db
            .prepare("SELECT name, filter, policy FROM channels")
            .map_err(sql_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(sql_err)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(sql_err)?);
        }
        Ok(out)
    }

    pub fn put_circle(&self, name: &str, members: &[PeerId]) -> Result<()> {
        let ids: Vec<String> = members.iter().map(|p| p.to_string()).collect();
        let body = ids.join(",");
        self.db
            .lock()
            .expect("db")
            .execute(
                "INSERT OR REPLACE INTO circles(name, members) VALUES(?1,?2)",
                params![name, body],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn circle_members(&self, name: &str) -> Result<Vec<PeerId>> {
        let s: String = self
            .db
            .lock()
            .expect("db")
            .query_row(
                "SELECT members FROM circles WHERE name=?1",
                params![name],
                |r| r.get(0),
            )
            .map_err(sql_err)?;
        let mut out = Vec::new();
        for p in s.split(',') {
            if let Ok(id) = p.parse() {
                out.push(id);
            }
        }
        Ok(out)
    }

    pub fn compact(&self) -> Result<u32> {
        let n = self.gc(unix_now())?;
        let _ = self
            .db
            .lock()
            .expect("db")
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;");
        Ok(n)
    }

    pub fn quotas(&self) -> &StorageQuotas {
        &self.quotas
    }

    pub fn kv_get(&self, k: &str) -> Result<Option<String>> {
        let db = self.db.lock().expect("db");
        db.query_row("SELECT v FROM kv WHERE k=?1", params![k], |r| r.get(0))
            .optional()
            .map_err(sql_err)
    }

    pub fn kv_set(&self, k: &str, v: &str) -> Result<()> {
        self.db
            .lock()
            .expect("db")
            .execute(
                "INSERT OR REPLACE INTO kv(k,v) VALUES(?1,?2)",
                params![k, v],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn touch_hour_hist(&self, peer: PeerId, now: u64) -> Result<()> {
        let key = format!("eh:{}", crate::hex_encode(peer.as_bytes()));
        let mut hist = [0u32; 24];
        if let Some(s) = self.kv_get(&key)?
            && let Ok(v) = serde_json::from_str::<Vec<u32>>(&s)
        {
            for (i, n) in v.into_iter().take(24).enumerate() {
                hist[i] = n;
            }
        }
        let hour = ((now % 86_400) / 3600) as usize;
        hist[hour] = hist[hour].saturating_add(1);
        self.kv_set(
            &key,
            &serde_json::to_string(&hist.to_vec()).unwrap_or_else(|_| "[]".into()),
        )
    }

    pub fn hour_hist(&self, peer: PeerId) -> Result<[u32; 24]> {
        let key = format!("eh:{}", crate::hex_encode(peer.as_bytes()));
        let mut hist = [0u32; 24];
        if let Some(s) = self.kv_get(&key)?
            && let Ok(v) = serde_json::from_str::<Vec<u32>>(&s)
        {
            for (i, n) in v.into_iter().take(24).enumerate() {
                hist[i] = n;
            }
        }
        Ok(hist)
    }

    pub fn put_receipt(&self, r: &crate::receipt::Receipt) -> Result<()> {
        let body = crate::protocol::encode_cbor(r)?;
        let rid = DefaultProvider.hash(crate::HashAlgorithm::Blake3, &body);
        self.db
            .lock()
            .expect("db")
            .execute(
                "INSERT OR REPLACE INTO receipts(receipt_id, object_id, kind, body) VALUES(?1,?2,?3,?4)",
                params![
                    rid.0.as_slice(),
                    r.object_id.as_bytes().as_slice(),
                    format!("{:?}", r.kind).to_lowercase(),
                    body
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn receipts_for(&self, id: &ObjectId) -> Result<Vec<crate::receipt::Receipt>> {
        let db = self.db.lock().expect("db");
        let mut stmt = db
            .prepare("SELECT body FROM receipts WHERE object_id=?1")
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![id.as_bytes().as_slice()], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .map_err(sql_err)?;
        let mut out = Vec::new();
        for row in rows {
            let b = row.map_err(sql_err)?;
            if let Ok(r) = crate::protocol::decode_cbor(&b) {
                out.push(r);
            }
        }
        Ok(out)
    }

    pub fn receipt_issuer_count(&self, id: &ObjectId) -> Result<u32> {
        let rs = self.receipts_for(id)?;
        let mut seen = std::collections::BTreeSet::new();
        for r in rs {
            seen.insert(*r.issuer.as_bytes());
        }
        Ok(seen.len() as u32)
    }

    /// Safe repair: indexes, WAL, unreferenced chunk files. Never deletes Drop objects.
    pub fn repair_safe(&self) -> Result<Vec<String>> {
        let mut notes = Vec::new();
        let n = self.compact()?;
        notes.push(format!("vacuum/gc rows={n} (local/pinned Drops kept)"));
        let chunk_dir = self.root.join("chunks");
        if let Ok(rd) = fs::read_dir(&chunk_dir) {
            let mut orphans = 0u32;
            for ent in rd.flatten() {
                let name = ent.file_name();
                let hex = name.to_string_lossy();
                let db = self.db.lock().expect("db");
                let n: i64 = db
                    .query_row(
                        "SELECT COUNT(*) FROM chunks WHERE lower(hex(content_id))=?1",
                        params![hex.to_ascii_lowercase()],
                        |r| r.get(0),
                    )
                    .unwrap_or(1);
                drop(db);
                if n == 0 {
                    let tmp = ent.path();
                    if tmp.extension().and_then(|e| e.to_str()) == Some("tmp") {
                        let _ = fs::remove_file(&tmp);
                        orphans += 1;
                    }
                }
            }
            if orphans > 0 {
                notes.push(format!("removed {orphans} temporary chunk files"));
            }
        }
        for lock in ["daemon.pid.lock", ".write-probe", "control.sock.lock"] {
            let p = self.root.join(lock);
            if p.exists() {
                let _ = fs::remove_file(&p);
                notes.push(format!("removed stale {lock}"));
            }
        }
        Ok(notes)
    }
}

#[derive(Debug, Clone)]
pub struct StoreStats {
    pub objects: u64,
    pub payloads: u64,
    pub chunks: u64,
    pub logical_size: u64,
    pub physical_size: u64,
}

impl StoreStats {
    pub fn dedup_ratio(&self) -> f64 {
        if self.logical_size == 0 {
            0.0
        } else {
            1.0 - (self.physical_size as f64 / self.logical_size as f64)
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncounterRow {
    pub first_seen: u64,
    pub last_seen: u64,
    pub encounter_count: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub successful_forwards: u64,
    pub failed_forwards: u64,
}

fn sql_err(e: rusqlite::Error) -> DdError {
    DdError::protocol(ErrorCode::Dds2004CorruptMetadata, e.to_string())
}

fn ownership_str(o: Ownership) -> &'static str {
    match o {
        Ownership::Local => "local",
        Ownership::Incoming => "incoming",
        Ownership::Relay => "relay",
        Ownership::Temporary => "temporary",
    }
}

fn parse_own(s: &str) -> Ownership {
    match s {
        "local" => Ownership::Local,
        "incoming" => Ownership::Incoming,
        "temporary" => Ownership::Temporary,
        _ => Ownership::Relay,
    }
}

fn parse_trust(s: &str) -> TrustState {
    match s {
        "verified" => TrustState::Verified,
        "known" => TrustState::Known,
        "blocked" => TrustState::Blocked,
        "observed" => TrustState::Observed,
        _ => TrustState::Unknown,
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn format_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    let x = n as f64;
    if x >= KB * KB * KB {
        format!("{:.1} GB", x / (KB * KB * KB))
    } else if x >= KB * KB {
        format!("{:.1} MB", x / (KB * KB))
    } else if x >= KB {
        format!("{:.1} KB", x / KB)
    } else {
        format!("{n} B")
    }
}
