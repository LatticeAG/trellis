//! Export writers (spec §7.4): streaming `trellis-stream/1` and the
//! `trellis-bundle/1` in-memory form. Exports pin a head at read time; a run
//! that stops afterwards does not retroactively attach a certificate.

use crate::json::Value;
use crate::store::Store;
use crate::types::Head;

/// Emit a stable-prefix stream export for `run_id` at head `through`.
/// Returns LF-terminated canonical-JSON lines.
pub fn stream_export(
    store: &Store,
    run_id: &str,
    through: &Head,
) -> Result<Vec<u8>, crate::types::ApiErr> {
    use crate::types::Code;
    let policy = store
        .run_policy(run_id)
        .map_err(|_| crate::types::ApiErr::new(Code::AuditFault))?
        .ok_or_else(|| crate::types::ApiErr::new(Code::NotFound))?;
    let checkpoint = store
        .checkpoint_at(run_id, through.seq)
        .map_err(|_| crate::types::ApiErr::new(Code::AuditFault))?
        .ok_or_else(|| crate::types::ApiErr::new(Code::NotFound))?;
    let header = Value::obj(vec![
        ("record", Value::str("header")),
        ("v", Value::int(1)),
        ("format", Value::str(crate::wire::EXPORT_FORMAT)),
        ("policy", policy),
        ("checkpoint", checkpoint),
    ]);
    let mut out = Vec::new();
    out.extend_from_slice(&header.canonical());
    out.push(b'\n');
    let mut count = 0u64;
    for (seq, body, sig, hash) in store
        .events_page(run_id, 0, through.seq, 256)
        .map_err(|_| crate::types::ApiErr::new(Code::AuditFault))?
        .into_iter()
    {
        let _ = seq;
        let line = Value::obj(vec![
            ("record", Value::str("entry")),
            (
                "entry",
                Value::obj(vec![
                    ("body", body),
                    ("hash", Value::str(hash)),
                    ("sig", Value::str(sig)),
                ]),
            ),
        ]);
        out.extend_from_slice(&line.canonical());
        out.push(b'\n');
        count += 1;
    }
    // certificate only when the pinned head is terminal RunStopped
    let cert = store
        .certificate_row(run_id)
        .map_err(|_| crate::types::ApiErr::new(Code::AuditFault))?;
    let cert = match cert {
        Some(c) => {
            // the certificate's stopped_event must equal this head
            let stopped = c
                .get("body")
                .and_then(|b| b.get("stopped_event"))
                .and_then(|s| crate::schema::head(s).ok());
            match stopped {
                Some(h) if &h == through => c,
                _ => Value::Null,
            }
        }
        None => Value::Null,
    };
    let trailer = Value::obj(vec![
        ("record", Value::str("trailer")),
        ("count", Value::str(count.to_string())),
        ("certificate", cert),
    ]);
    out.extend_from_slice(&trailer.canonical());
    out.push(b'\n');
    Ok(out)
}

/// Emit the in-memory bundle for a run at a head.
pub fn bundle_export(
    store: &Store,
    run_id: &str,
    through: &Head,
) -> Result<Value, crate::types::ApiErr> {
    use crate::types::Code;
    let policy = store
        .run_policy(run_id)
        .map_err(|_| crate::types::ApiErr::new(Code::AuditFault))?
        .ok_or_else(|| crate::types::ApiErr::new(Code::NotFound))?;
    let checkpoint = store
        .checkpoint_at(run_id, through.seq)
        .map_err(|_| crate::types::ApiErr::new(Code::AuditFault))?
        .ok_or_else(|| crate::types::ApiErr::new(Code::NotFound))?;
    let mut entries = Vec::new();
    for (_seq, body, sig, hash) in store
        .events_page(run_id, 0, through.seq, 256)
        .map_err(|_| crate::types::ApiErr::new(Code::AuditFault))?
    {
        entries.push(Value::obj(vec![
            ("body", body),
            ("hash", Value::str(hash)),
            ("sig", Value::str(sig)),
        ]));
    }
    let cert = store
        .certificate_row(run_id)
        .map_err(|_| crate::types::ApiErr::new(Code::AuditFault))?
        .and_then(|c| {
            let stopped = c
                .get("body")
                .and_then(|b| b.get("stopped_event"))
                .and_then(|s| crate::schema::head(s).ok());
            match stopped {
                Some(h) if &h == through => Some(c),
                _ => None,
            }
        })
        .unwrap_or(Value::Null);
    Ok(Value::obj(vec![
        ("v", Value::int(1)),
        ("format", Value::str("trellis-bundle/1")),
        ("policy", policy),
        ("entries", Value::Arr(entries)),
        ("checkpoint", checkpoint),
        ("certificate", cert),
    ]))
}
