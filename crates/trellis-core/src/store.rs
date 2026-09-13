//! Durable state: the exact §7.2 SQLite schema. WAL, synchronous=FULL,
//! foreign_keys=ON, busy_timeout=100. Objects are stored as canonical UTF-8
//! blobs; sequence values are checked signed-64-bit integers.
//!
//! `CommitFault` injection exists solely so the conformance harness can model
//! fsync failure/blocking at a commit boundary; production never sets it.

use crate::json::Value;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=100;
CREATE TABLE IF NOT EXISTS meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, policy_hash TEXT NOT NULL,
  policy BLOB NOT NULL, manifest BLOB NOT NULL, projection BLOB NOT NULL,
  last_seq INTEGER NOT NULL CHECK(last_seq>=1), last_hash TEXT NOT NULL,
  task_uid INTEGER NOT NULL, workspace TEXT NOT NULL, terminal INTEGER NOT NULL CHECK(terminal IN(0,1))
);
CREATE TABLE IF NOT EXISTS events (
  run_id TEXT NOT NULL REFERENCES runs(run_id), seq INTEGER NOT NULL CHECK(seq>=1),
  event_id TEXT NOT NULL UNIQUE, hash TEXT NOT NULL UNIQUE, body BLOB NOT NULL, sig BLOB NOT NULL,
  PRIMARY KEY(run_id,seq)
);
CREATE TABLE IF NOT EXISTS requests (
  principal TEXT NOT NULL, scope TEXT NOT NULL, request_id TEXT NOT NULL,
  digest TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN('PENDING','FINAL')),
  response BLOB, PRIMARY KEY(principal,scope,request_id),
  CHECK((status='PENDING' AND response IS NULL) OR (status='FINAL' AND response IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS challenges (
  run_id TEXT PRIMARY KEY REFERENCES runs(run_id), seq INTEGER NOT NULL,
  challenge BLOB NOT NULL, state TEXT NOT NULL CHECK(state IN('OUTSTANDING','CONSUMED','EXPIRED','INVALIDATED'))
);
CREATE TABLE IF NOT EXISTS checkpoints (
  run_id TEXT NOT NULL REFERENCES runs(run_id), seq INTEGER NOT NULL, body BLOB NOT NULL,
  hash TEXT NOT NULL, sig BLOB NOT NULL, PRIMARY KEY(run_id,seq)
);
CREATE TABLE IF NOT EXISTS certificates (run_id TEXT PRIMARY KEY REFERENCES runs(run_id), body BLOB NOT NULL, hash TEXT NOT NULL, sig BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS leases (kind TEXT NOT NULL CHECK(kind IN('uid','workspace')), value TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES runs(run_id), PRIMARY KEY(kind,value));
"#;

#[derive(Debug)]
pub enum StoreErr {
    Db(rusqlite::Error),
    /// Injected fsync EIO: the transaction did not commit.
    FaultEio,
    /// Injected fsync block: the transaction is stuck until released.
    FaultBlocked,
}

impl From<rusqlite::Error> for StoreErr {
    fn from(e: rusqlite::Error) -> Self {
        StoreErr::Db(e)
    }
}

/// A durable batch: everything written in one FULL-durability transaction.
#[derive(Default)]
pub struct Batch {
    pub new_run: Option<NewRun>,
    pub events: Vec<EventRow>,
    pub run_update: Option<RunUpdate>,
    pub challenge: Option<ChallengeRow>,
    pub requests: Vec<RequestRow>,
    pub checkpoint: Option<SignedRow>,
    pub certificate: Option<SignedRow>,
    pub leases: Vec<LeaseRow>,
    pub meta: Option<Value>,
}

pub struct NewRun {
    pub run_id: String,
    pub agent_id: String,
    pub policy_hash: String,
    pub policy: Value,
    pub manifest: Value,
    pub projection: Value,
    pub last_seq: u64,
    pub last_hash: String,
    pub task_uid: u64,
    pub workspace: String,
    pub terminal: bool,
}

pub struct RunUpdate {
    pub run_id: String,
    pub projection: Value,
    pub last_seq: u64,
    pub last_hash: String,
    pub terminal: bool,
}

pub struct EventRow {
    pub run_id: String,
    pub seq: u64,
    pub event_id: String,
    pub hash: String,
    pub body: Value,
    pub sig: String,
}

pub struct ChallengeRow {
    pub run_id: String,
    pub seq: u64,
    pub challenge: Value,
    pub state: &'static str,
}

pub struct RequestRow {
    pub principal: String,
    pub scope: String,
    pub request_id: String,
    pub digest: String,
    pub status: &'static str, // PENDING | FINAL
    pub response: Option<Value>,
}

pub struct SignedRow {
    pub run_id: String,
    pub seq: u64,
    pub body: Value,
    pub hash: String,
    pub sig: String,
}

pub struct LeaseRow {
    pub kind: &'static str, // uid | workspace
    pub value: String,
    pub run_id: String,
}

fn u64_i64(v: u64) -> Result<i64, StoreErr> {
    i64::try_from(v).map_err(|_| {
        StoreErr::Db(rusqlite::Error::ToSqlConversionFailure(Box::new(
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "u64 out of i64 range"),
        )))
    })
}

pub struct Store {
    pub conn: Connection,
    /// Test-only fault injector checked at each commit boundary.
    pub fault: Option<StoreErr>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Store, StoreErr> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn, fault: None })
    }
    pub fn memory() -> Result<Store, StoreErr> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn, fault: None })
    }

    pub fn commit(&mut self, b: Batch) -> Result<(), StoreErr> {
        if let Some(f) = self.fault.take() {
            return Err(match f {
                StoreErr::FaultBlocked => StoreErr::FaultBlocked,
                StoreErr::FaultEio => StoreErr::FaultEio,
                StoreErr::Db(e) => StoreErr::Db(e),
            });
        }
        let tx = self.conn.transaction()?;
        if let Some(m) = &b.meta {
            tx.execute(
                "INSERT INTO meta(singleton,body) VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET body=excluded.body",
                params![m.canonical()],
            )?;
        }
        if let Some(r) = &b.new_run {
            tx.execute(
                "INSERT INTO runs(run_id,agent_id,policy_hash,policy,manifest,projection,last_seq,last_hash,task_uid,workspace,terminal)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    r.run_id,
                    r.agent_id,
                    r.policy_hash,
                    r.policy.canonical(),
                    r.manifest.canonical(),
                    r.projection.canonical(),
                    u64_i64(r.last_seq)?,
                    r.last_hash,
                    u64_i64(r.task_uid)?,
                    r.workspace,
                    r.terminal as i64
                ],
            )?;
        }
        for e in &b.events {
            tx.execute(
                "INSERT INTO events(run_id,seq,event_id,hash,body,sig) VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    e.run_id,
                    u64_i64(e.seq)?,
                    e.event_id,
                    e.hash,
                    e.body.canonical(),
                    e.sig
                ],
            )?;
        }
        if let Some(u) = &b.run_update {
            tx.execute(
                "UPDATE runs SET projection=?1,last_seq=?2,last_hash=?3,terminal=?4 WHERE run_id=?5",
                params![
                    u.projection.canonical(),
                    u64_i64(u.last_seq)?,
                    u.last_hash,
                    u.terminal as i64,
                    u.run_id
                ],
            )?;
        }
        if let Some(c) = &b.challenge {
            tx.execute(
                "INSERT INTO challenges(run_id,seq,challenge,state) VALUES(?1,?2,?3,?4)
                 ON CONFLICT(run_id) DO UPDATE SET seq=excluded.seq,challenge=excluded.challenge,state=excluded.state",
                params![c.run_id, u64_i64(c.seq)?, c.challenge.canonical(), c.state],
            )?;
        }
        for r in &b.requests {
            tx.execute(
                "INSERT INTO requests(principal,scope,request_id,digest,status,response) VALUES(?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(principal,scope,request_id) DO UPDATE SET status=excluded.status,response=excluded.response",
                params![
                    r.principal,
                    r.scope,
                    r.request_id,
                    r.digest,
                    r.status,
                    r.response.as_ref().map(|v| v.canonical())
                ],
            )?;
        }
        if let Some(c) = &b.checkpoint {
            tx.execute(
                "INSERT INTO checkpoints(run_id,seq,body,hash,sig) VALUES(?1,?2,?3,?4,?5)",
                params![c.run_id, u64_i64(c.seq)?, c.body.canonical(), c.hash, c.sig],
            )?;
        }
        if let Some(c) = &b.certificate {
            tx.execute(
                "INSERT INTO certificates(run_id,body,hash,sig) VALUES(?1,?2,?3,?4)",
                params![c.run_id, c.body.canonical(), c.hash, c.sig],
            )?;
        }
        for l in &b.leases {
            tx.execute(
                "INSERT INTO leases(kind,value,run_id) VALUES(?1,?2,?3)",
                params![l.kind, l.value, l.run_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Delete lease rows for a run (on positive empty confirmation).
    pub fn release_leases(&mut self, run_id: &str) -> Result<(), StoreErr> {
        self.conn
            .execute("DELETE FROM leases WHERE run_id=?1", params![run_id])?;
        Ok(())
    }

    // ---- reads -----------------------------------------------------------

    pub fn meta(&self) -> Result<Option<Value>, StoreErr> {
        let v: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT body FROM meta WHERE singleton=1", [], |r| r.get(0))
            .optional()?;
        match v {
            Some(b) => {
                Ok(Some(crate::json::parse(&b).map_err(|_| {
                    StoreErr::Db(rusqlite::Error::InvalidQuery)
                })?))
            }
            None => Ok(None),
        }
    }

    pub fn load_runs(&self) -> Result<Vec<RunRow>, StoreErr> {
        let mut st = self.conn.prepare(
            "SELECT run_id,agent_id,policy_hash,policy,manifest,projection,last_seq,last_hash,task_uid,workspace,terminal FROM runs ORDER BY run_id",
        )?;
        let rows = st
            .query_map([], |r| {
                Ok(RunRow {
                    run_id: r.get(0)?,
                    agent_id: r.get(1)?,
                    policy_hash: r.get(2)?,
                    policy: r.get::<_, Vec<u8>>(3)?,
                    manifest: r.get::<_, Vec<u8>>(4)?,
                    projection: r.get::<_, Vec<u8>>(5)?,
                    last_seq: r.get::<_, i64>(6)? as u64,
                    last_hash: r.get(7)?,
                    task_uid: r.get::<_, i64>(8)? as u64,
                    workspace: r.get(9)?,
                    terminal: r.get::<_, i64>(10)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn load_events(&self, run_id: &str) -> Result<Vec<(u64, Value, String)>, StoreErr> {
        let mut st = self
            .conn
            .prepare("SELECT seq,body,sig FROM events WHERE run_id=?1 ORDER BY seq")?;
        let rows = st
            .query_map(params![run_id], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut out = Vec::new();
        for (seq, body, sig) in rows {
            out.push((
                seq,
                crate::json::parse(&body)
                    .map_err(|_| StoreErr::Db(rusqlite::Error::InvalidQuery))?,
                sig,
            ));
        }
        Ok(out)
    }

    pub fn event_at(&self, run_id: &str, seq: u64) -> Result<Option<Value>, StoreErr> {
        let v: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT body FROM events WHERE run_id=?1 AND seq=?2",
                params![run_id, seq as i64],
                |r| r.get(0),
            )
            .optional()?;
        match v {
            Some(b) => {
                Ok(Some(crate::json::parse(&b).map_err(|_| {
                    StoreErr::Db(rusqlite::Error::InvalidQuery)
                })?))
            }
            None => Ok(None),
        }
    }

    pub fn event_entry_at(
        &self,
        run_id: &str,
        seq: u64,
    ) -> Result<Option<(Value, String, String)>, StoreErr> {
        let v: Option<(Vec<u8>, String, String)> = self
            .conn
            .query_row(
                "SELECT body,sig,hash FROM events WHERE run_id=?1 AND seq=?2",
                params![run_id, seq as i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        match v {
            Some((b, sig, hash)) => Ok(Some((
                crate::json::parse(&b).map_err(|_| StoreErr::Db(rusqlite::Error::InvalidQuery))?,
                sig,
                hash,
            ))),
            None => Ok(None),
        }
    }

    pub fn events_page(
        &self,
        run_id: &str,
        after_seq: u64,
        through_seq: u64,
        limit: u64,
    ) -> Result<Vec<(u64, Value, String, String)>, StoreErr> {
        let mut st = self.conn.prepare(
            "SELECT seq,body,sig,hash FROM events WHERE run_id=?1 AND seq>?2 AND seq<=?3 ORDER BY seq LIMIT ?4",
        )?;
        let rows = st
            .query_map(
                params![run_id, after_seq as i64, through_seq as i64, limit as i64],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)? as u64,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let mut out = Vec::new();
        for (seq, b, sig, hash) in rows {
            out.push((
                seq,
                crate::json::parse(&b).map_err(|_| StoreErr::Db(rusqlite::Error::InvalidQuery))?,
                sig,
                hash,
            ));
        }
        Ok(out)
    }

    pub fn request_lookup(
        &self,
        principal: &str,
        scope: &str,
        request_id: &str,
    ) -> Result<Option<(String, String, Option<Value>)>, StoreErr> {
        let v: Option<(String, String, Option<Vec<u8>>)> = self
            .conn
            .query_row(
                "SELECT digest,status,response FROM requests WHERE principal=?1 AND scope=?2 AND request_id=?3",
                params![principal, scope, request_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        match v {
            Some((d, s, r)) => Ok(Some((
                d,
                s,
                r.map(|b| crate::json::parse(&b).unwrap_or(Value::Null)),
            ))),
            None => Ok(None),
        }
    }

    /// HeartbeatAccepted challenge_ids ever persisted for this run.
    pub fn consumed_challenges(&self, run_id: &str) -> Result<Vec<String>, StoreErr> {
        // scan event kinds in Rust (canonical blobs, no json_extract).
        let evs = self.load_events(run_id)?;
        let mut out = Vec::new();
        for (_, body, _) in evs {
            if body.get("kind").and_then(|k| k.as_str()) == Some("HeartbeatAccepted") {
                if let Some(cid) = body
                    .get("data")
                    .and_then(|d| d.get("challenge_id"))
                    .and_then(|c| c.as_str())
                {
                    out.push(cid.to_string());
                }
            }
        }
        Ok(out)
    }

    pub fn challenge_row(&self, run_id: &str) -> Result<Option<(u64, Value, String)>, StoreErr> {
        let v: Option<(i64, Vec<u8>, String)> = self
            .conn
            .query_row(
                "SELECT seq,challenge,state FROM challenges WHERE run_id=?1",
                params![run_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        match v {
            Some((s, c, st)) => Ok(Some((
                s as u64,
                crate::json::parse(&c).map_err(|_| StoreErr::Db(rusqlite::Error::InvalidQuery))?,
                st,
            ))),
            None => Ok(None),
        }
    }

    pub fn checkpoint_at(&self, run_id: &str, seq: u64) -> Result<Option<Value>, StoreErr> {
        let v: Option<(Vec<u8>, String, String)> = self
            .conn
            .query_row(
                "SELECT body,hash,sig FROM checkpoints WHERE run_id=?1 AND seq=?2",
                params![run_id, seq as i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(v.map(|(b, h, s)| {
            Value::obj(vec![
                ("body", crate::json::parse(&b).unwrap_or(Value::Null)),
                ("hash", Value::str(h)),
                ("sig", Value::str(s)),
            ])
        }))
    }

    pub fn certificate_row(&self, run_id: &str) -> Result<Option<Value>, StoreErr> {
        let v: Option<(Vec<u8>, String, String)> = self
            .conn
            .query_row(
                "SELECT body,hash,sig FROM certificates WHERE run_id=?1",
                params![run_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(v.map(|(b, h, s)| {
            Value::obj(vec![
                ("body", crate::json::parse(&b).unwrap_or(Value::Null)),
                ("hash", Value::str(h)),
                ("sig", Value::str(s)),
            ])
        }))
    }

    pub fn pending_requests(&self) -> Result<Vec<RequestRowOwned>, StoreErr> {
        let mut st = self.conn.prepare(
            "SELECT principal,scope,request_id,digest,status,response FROM requests WHERE status='PENDING'",
        )?;
        let rows = st
            .query_map([], |r| {
                Ok(RequestRowOwned {
                    principal: r.get(0)?,
                    scope: r.get(1)?,
                    request_id: r.get(2)?,
                    digest: r.get(3)?,
                    status: r.get::<_, String>(4)?,
                    response: r.get::<_, Option<Vec<u8>>>(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn count_active_runs(&self) -> Result<u64, StoreErr> {
        let n: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM runs WHERE terminal=0", [], |r| {
                    r.get(0)
                })?;
        Ok(n as u64)
    }

    pub fn lease_count(&self, kind: &str) -> Result<u64, StoreErr> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM leases WHERE kind=?1",
            params![kind],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    pub fn leased(&self, kind: &str, value: &str) -> Result<bool, StoreErr> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM leases WHERE kind=?1 AND value=?2",
            params![kind, value],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Raw canonical policy blob for a run.
    pub fn run_policy(&self, run_id: &str) -> Result<Option<Value>, StoreErr> {
        let v: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT policy FROM runs WHERE run_id=?1",
                params![run_id],
                |r| r.get(0),
            )
            .optional()?;
        match v {
            Some(b) => {
                Ok(Some(crate::json::parse(&b).map_err(|_| {
                    StoreErr::Db(rusqlite::Error::InvalidQuery)
                })?))
            }
            None => Ok(None),
        }
    }

    pub fn run_manifest(&self, run_id: &str) -> Result<Option<Value>, StoreErr> {
        let v: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT manifest FROM runs WHERE run_id=?1",
                params![run_id],
                |r| r.get(0),
            )
            .optional()?;
        match v {
            Some(b) => {
                Ok(Some(crate::json::parse(&b).map_err(|_| {
                    StoreErr::Db(rusqlite::Error::InvalidQuery)
                })?))
            }
            None => Ok(None),
        }
    }

    pub fn used_uids(&self) -> Result<Vec<u64>, StoreErr> {
        let mut st = self
            .conn
            .prepare("SELECT value FROM leases WHERE kind='uid'")?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows.iter().filter_map(|s| s.parse().ok()).collect())
    }
}

pub struct RunRow {
    pub run_id: String,
    pub agent_id: String,
    pub policy_hash: String,
    pub policy: Vec<u8>,
    pub manifest: Vec<u8>,
    pub projection: Vec<u8>,
    pub last_seq: u64,
    pub last_hash: String,
    pub task_uid: u64,
    pub workspace: String,
    pub terminal: bool,
}

pub struct RequestRowOwned {
    pub principal: String,
    pub scope: String,
    pub request_id: String,
    pub digest: String,
    pub status: String,
    pub response: Option<Vec<u8>>,
}
