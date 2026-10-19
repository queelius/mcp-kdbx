//! `View`: a kdbx-core snapshot of a keepass database plus its path index.
//!
//! Every path mcp-kdbx parses, formats or resolves goes through kdbx-core's
//! one path grammar (`kdbx_core::path`), which works on a
//! [`Snapshot`](kdbx_core::model::Snapshot), not on a live
//! `keepass::Database`. A `View` is that snapshot, captured from a database
//! under fingerprint sealing (no secret value is copied into it), together
//! with a [`PathIndex`] of every node, computed in one pass, and the set of
//! entries whose TOTP configuration resolves (computed from the live entries
//! at capture, since the snapshot seals the OTP secret). Paths are resolved
//! against the snapshot to a record UUID, which [`entry_id`] and [`group_id`]
//! then map back to the live keepass record.
//!
//! The read views are built from a `View` alone, so they cannot emit a
//! secret by construction: the snapshot has none to give. Only the reveal
//! tools read the live database.
//!
//! The vault caches one `View` of its working database per generation (see
//! `Vault::view`): any mutable access to the working db, a discard, a save,
//! a lock and an unlock drop it, and the next read captures a fresh one.

use kdbx_core::capture::keepass_0_12::capture;
use kdbx_core::fingerprint::FingerprintKey;
use kdbx_core::model::NodeIndex;
use kdbx_core::model::{Sealing, Snapshot};
use kdbx_core::path::{PathIndex, VaultPath};
use keepass::Database;
use keepass::db::{EntryId, GroupId};
use std::collections::HashSet;
use uuid::Uuid;
use zeroize::Zeroize;

/// A snapshot of a database and the canonical path of each of its nodes.
#[derive(Debug)]
pub struct View {
    snapshot: Snapshot,
    paths: PathIndex,
    with_otp: HashSet<Uuid>,
}

impl View {
    /// Capture `db` under fingerprint sealing with `key` and index its paths.
    pub fn capture(db: &Database, key: &FingerprintKey) -> View {
        let snapshot = capture(db, &Sealing::Fingerprint(key));
        let paths = PathIndex::new(&snapshot);
        let with_otp = db
            .iter_all_entries()
            .filter(|entry| crate::engine::otp::has_otp(entry))
            .map(|entry| entry.id().uuid())
            .collect();
        View {
            snapshot,
            paths,
            with_otp,
        }
    }

    /// Capture `db` with a fresh [`ephemeral_key`], for a caller that needs
    /// only the tree (paths and UUIDs), not fingerprints it can compare later.
    pub fn capture_ephemeral(db: &Database) -> View {
        View::capture(db, &ephemeral_key())
    }

    /// The snapshot.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// The canonical path of the group or entry `uuid`, or `None` when it has
    /// no addressable path (an empty title or group name on the way) or is
    /// unknown.
    pub fn path(&self, uuid: Uuid) -> Option<&VaultPath> {
        self.paths.get(uuid)
    }

    /// [`path`](Self::path) in its canonical string form.
    pub fn path_string(&self, uuid: Uuid) -> Option<String> {
        self.path(uuid).map(VaultPath::format)
    }

    /// Whether the entry `uuid` has a usable TOTP configuration (the
    /// `has_otp` flag: true exactly when `kdbx_get_otp` would produce a code).
    pub fn has_otp(&self, uuid: Uuid) -> bool {
        self.with_otp.contains(&uuid)
    }

    /// A [`NodeIndex`] of the snapshot: one linear walk, then constant-time
    /// node and parent lookups. A caller doing many lookups (the search, the
    /// stage diff) builds one per call and passes it on; it borrows the
    /// snapshot, so it is not stored in the view.
    pub fn nodes(&self) -> NodeIndex<'_> {
        NodeIndex::new(&self.snapshot)
    }

    /// The canonical path of the group that holds node `uuid`, as a string
    /// (`None` for the root, an unknown node, or a group with no addressable
    /// path). `nodes` is this view's [`nodes`](Self::nodes); the lookup is
    /// constant-time.
    pub fn parent_path_string(&self, nodes: &NodeIndex<'_>, uuid: Uuid) -> Option<String> {
        self.path_string(nodes.parent(uuid)?.uuid)
    }
}

/// A fingerprint key for a single use: 32 bytes from the OS random number
/// generator. A snapshot compared or indexed only within one call needs no
/// stable key, and a random one costs nothing (no KDF) and makes every
/// fingerprint meaningless outside that call.
///
/// Panics only if the OS random number generator fails, as
/// `uuid::Uuid::new_v4` and keepass's own save path (which draws fresh
/// nonces) would.
pub fn ephemeral_key() -> FingerprintKey {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the OS random number generator failed");
    let key = FingerprintKey::from_bytes(bytes);
    bytes.zeroize();
    key
}

/// The live keepass id of the entry with record UUID `uuid` (history items
/// are not entries).
pub fn entry_id(db: &Database, uuid: Uuid) -> Option<EntryId> {
    db.iter_all_entries()
        .map(|e| e.id())
        .find(|id| id.uuid() == uuid)
}

/// The live keepass id of the group with record UUID `uuid`, including the
/// root.
pub fn group_id(db: &Database, uuid: Uuid) -> Option<GroupId> {
    db.iter_all_groups()
        .map(|g| g.id())
        .find(|id| id.uuid() == uuid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::fields;

    #[test]
    fn ephemeral_keys_differ() {
        let a = ephemeral_key().fingerprint(kdbx_core::fingerprint::Domain::Field, b"x");
        let b = ephemeral_key().fingerprint(kdbx_core::fingerprint::Domain::Field, b"x");
        assert_ne!(a, b, "two ephemeral keys must not collide");
    }

    #[test]
    fn parent_paths_from_the_node_index_agree_with_the_snapshot_walk() {
        let mut db = Database::new();
        let web = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "Web".to_string())
            .id();
        let unnamed = db.group_mut(web).unwrap().add_group().id();
        for group in [web, unnamed] {
            db.group_mut(group).unwrap().add_entry().edit(|e| {
                e.set_unprotected(fields::TITLE, "Mail");
            });
        }
        db.root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected(fields::TITLE, "Top"));
        let view = View::capture_ephemeral(&db);
        let nodes = view.nodes();
        for (node, _) in view.snapshot().walk() {
            let walked = view
                .snapshot()
                .parent_of(node.uuid())
                .and_then(|p| view.path_string(p.uuid));
            assert_eq!(view.parent_path_string(&nodes, node.uuid()), walked);
        }
        // The root has no parent; an entry under an unnamed group has a
        // parent with no addressable path.
        assert_eq!(
            view.parent_path_string(&nodes, view.snapshot().root.uuid),
            None
        );
    }

    #[test]
    fn view_paths_name_live_records_and_seal_secrets() {
        let mut db = Database::new();
        let web = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "Web".to_string())
            .id();
        let entry = db
            .group_mut(web)
            .unwrap()
            .add_entry()
            .edit(|e| {
                e.set_unprotected(fields::TITLE, "Mail");
                e.set_protected(fields::PASSWORD, "hunter2");
            })
            .id();
        let view = View::capture_ephemeral(&db);
        assert_eq!(view.path_string(entry.uuid()).as_deref(), Some("/Web/Mail"));
        assert_eq!(view.path_string(web.uuid()).as_deref(), Some("/Web/"));
        assert_eq!(
            view.path_string(db.root().id().uuid()).as_deref(),
            Some("/")
        );
        assert_eq!(
            view.parent_path_string(&view.nodes(), entry.uuid())
                .as_deref(),
            Some("/Web/")
        );
        assert_eq!(entry_id(&db, entry.uuid()), Some(entry));
        assert_eq!(group_id(&db, web.uuid()), Some(web));
        assert!(!format!("{:?}", view.snapshot()).contains("hunter2"));
    }
}
