//! Generate the committed KDBX test fixtures under `tests/fixtures/`.
//!
//! Run once (and re-run when the fixture set changes) with:
//!
//! ```text
//! cargo run --features cli --bin gen-fixtures
//! ```
//!
//! Every fixture is encrypted with the password [`PASSWORD`]
//! (`test-password-do-not-use`), the same throwaway password `web-kdbx` and
//! `diff-kdbx` use. The fixtures are committed so the integration and
//! protocol-conformance suites do not regenerate them on every run.
//!
//! Byte-stable regeneration is not a goal: keepass 0.12 assigns random UUIDs to
//! new entries and groups (the `add_*_with_id` constructors are not public in
//! the released crate), and KDBX4 uses a fresh nonce on every save, so two runs
//! of this generator never produce identical bytes. The tests therefore assert
//! against observed contents (titles, paths, field shapes), not fixed UUIDs.
//! `tests/fixtures/MANIFEST.md` is the human-readable description of what each
//! file should contain; a test failure there means a fixture drifted from the
//! manifest.

use std::path::{Path, PathBuf};

use keepass::Database;
use keepass::DatabaseKey;
use keepass::db::{GroupId, Value, fields};

/// The password every fixture is encrypted with. Throwaway, never a real
/// secret, and shared with the sibling repos so a person can open any fixture
/// the same way.
const PASSWORD: &str = "test-password-do-not-use";

fn main() {
    let dir = fixtures_dir();
    std::fs::create_dir_all(&dir).expect("create tests/fixtures directory");

    write_fixture(&dir.join("empty.kdbx"), build_empty());
    write_fixture(&dir.join("flat.kdbx"), build_flat());
    write_fixture(&dir.join("nested.kdbx"), build_nested());
    write_fixture(&dir.join("with_attachments.kdbx"), build_with_attachments());
    write_fixture(&dir.join("with_otp.kdbx"), build_with_otp());
    write_fixture(&dir.join("duplicates.kdbx"), build_duplicates());
    write_fixture(&dir.join("kdbx41.kdbx"), build_kdbx41());

    println!("done. fixtures written to {}", dir.display());
}

/// The `tests/fixtures` directory, resolved against the crate root so the
/// generator works regardless of the current working directory.
fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Encrypt `db` with [`PASSWORD`] and write it to `path`, overwriting any
/// existing file.
fn write_fixture(path: &Path, db: Database) {
    let mut buf = Vec::new();
    db.save(&mut buf, DatabaseKey::new().with_password(PASSWORD))
        .expect("encrypt and serialize fixture");
    std::fs::write(path, &buf).expect("write fixture file");
    println!("wrote {} ({} bytes)", path.display(), buf.len());
}

/// `kdbx41.kdbx`: one entry in a file whose header says KDBX 4.1. keepass 0.12
/// saves KDBX 4.1 lossily (it drops entry-level 4.1 data it reads), so the
/// server opens this vault read-only: reads work, writes return
/// FORMAT_READ_ONLY. Written by keepass 0.12 itself, so it holds no 4.1 data;
/// the header version alone decides, as it must (0.12 has already dropped
/// any 4.1 data by the time the server could look).
fn build_kdbx41() -> Database {
    let mut db = Database::new();
    db.config.version = keepass::config::DatabaseVersion::KDB4(1);
    db.root_mut().add_entry().edit(|e| {
        e.set_unprotected(fields::TITLE, "Note");
        e.set_unprotected(fields::USERNAME, "carol");
        e.set_protected(fields::PASSWORD, "kdbx41-secret-ghi");
    });
    db
}

/// `empty.kdbx`: a valid vault with no entries and no subgroups (root only).
/// Exercises the zero-entry list shapes and an unlock that has nothing to read.
fn build_empty() -> Database {
    Database::new()
}

/// `flat.kdbx`: five entries directly under the root group, covering the field
/// shapes the read and reveal tools care about:
///
/// - standard fields (username, url) and the implicitly protected password,
/// - a custom protected field (`Bank.PIN`) for the reveal-protected happy path,
/// - a custom unprotected field (`Server.Port`) for the FIELD_NOT_PROTECTED path,
/// - an entry with neither username nor url (`Wifi`).
fn build_flat() -> Database {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();

        let mut github = root.add_entry();
        github.edit(|e| {
            e.set_unprotected(fields::TITLE, "GitHub");
            e.set_unprotected(fields::USERNAME, "octocat");
            e.set_unprotected(fields::URL, "https://github.com");
            e.set_unprotected(fields::NOTES, "primary dev account");
            e.set_protected(fields::PASSWORD, "gh-secret-123");
        });

        let mut bank = root.add_entry();
        bank.edit(|e| {
            e.set_unprotected(fields::TITLE, "Bank");
            e.set_unprotected(fields::USERNAME, "alice");
            e.set_unprotected(fields::URL, "https://bank.example.com");
            e.set_protected(fields::PASSWORD, "bank-secret-456");
            // Custom protected field: the reveal-protected target.
            e.set_protected("PIN", "4321");
        });

        let mut email = root.add_entry();
        email.edit(|e| {
            e.set_unprotected(fields::TITLE, "Email");
            e.set_unprotected(fields::USERNAME, "alice@example.com");
            e.set_unprotected(fields::URL, "https://mail.example.com");
            e.set_protected(fields::PASSWORD, "email-secret-789");
        });

        let mut server = root.add_entry();
        server.edit(|e| {
            e.set_unprotected(fields::TITLE, "Server");
            e.set_unprotected(fields::USERNAME, "root");
            e.set_unprotected(fields::URL, "ssh://server.example.com");
            e.set_protected(fields::PASSWORD, "server-secret-abc");
            // Custom unprotected field: a reveal here must report
            // FIELD_NOT_PROTECTED.
            e.set_unprotected("Port", "22");
        });

        let mut wifi = root.add_entry();
        wifi.edit(|e| {
            e.set_unprotected(fields::TITLE, "Wifi");
            e.set_protected(fields::PASSWORD, "wifi-secret-def");
        });
    }
    db
}

/// `nested.kdbx`: three levels of group nesting under the root,
/// `Personal / Finance / Banking`, with one entry in the deepest group. The
/// path tools resolve `/Personal/Finance/Banking` and the entry beneath it.
fn build_nested() -> Database {
    let mut db = Database::new();

    // Sequenced into separate statements: chaining db_root(&mut db) as an
    // argument to named_subgroup(&mut db, ..) would borrow db mutably twice in
    // one expression.
    let root = db_root(&mut db);
    let personal = named_subgroup(&mut db, root, "Personal");
    let finance = named_subgroup(&mut db, personal, "Finance");
    let banking = named_subgroup(&mut db, finance, "Banking");

    {
        let mut g = db.group_mut(banking).expect("banking group exists");
        let mut account = g.add_entry();
        account.edit(|e| {
            e.set_unprotected(fields::TITLE, "Checking Account");
            e.set_unprotected(fields::USERNAME, "alice");
            e.set_unprotected(fields::URL, "https://bank.example.com");
            e.set_protected(fields::PASSWORD, "checking-secret-xyz");
        });
    }
    db
}

/// `with_attachments.kdbx`: two entries in the root, each carrying one binary
/// attachment. `Document A` holds a short text file; `Document B` holds the 256
/// bytes `0x00..=0xff`, which round-trips base64 through the download tool.
fn build_with_attachments() -> Database {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();

        let mut doc_a = root.add_entry();
        doc_a.edit(|e| {
            e.set_unprotected(fields::TITLE, "Document A");
            e.set_unprotected(fields::USERNAME, "alice");
        });
        doc_a.add_attachment("notes.txt", Value::unprotected(b"meeting notes\n".to_vec()));

        let mut doc_b = root.add_entry();
        doc_b.edit(|e| {
            e.set_unprotected(fields::TITLE, "Document B");
            e.set_unprotected(fields::USERNAME, "bob");
        });
        let all_bytes: Vec<u8> = (0u8..=255).collect();
        doc_b.add_attachment("data.bin", Value::unprotected(all_bytes));
    }
    db
}

/// `with_otp.kdbx`: one entry whose `otp` field carries an otpauth URI. The
/// secret `JBSWY3DPEHPK3PXP` is the canonical RFC 6238 test seed, so a code can
/// always be produced for the get-otp happy path.
fn build_with_otp() -> Database {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut totp = root.add_entry();
        totp.edit(|e| {
            e.set_unprotected(fields::TITLE, "TOTP Account");
            e.set_unprotected(fields::USERNAME, "alice");
            e.set_protected(
                fields::OTP,
                "otpauth://totp/Example:alice@example.com\
                 ?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=30&digits=6&algorithm=SHA1",
            );
        });
    }
    db
}

/// `duplicates.kdbx`: two entries in the root with the same title, `Duplicate`,
/// distinguished only by username. The path resolver must address them by the
/// `:1` / `:2` ordinal suffix.
fn build_duplicates() -> Database {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();

        let mut first = root.add_entry();
        first.edit(|e| {
            e.set_unprotected(fields::TITLE, "Duplicate");
            e.set_unprotected(fields::USERNAME, "first-account");
            e.set_protected(fields::PASSWORD, "first-secret");
        });

        let mut second = root.add_entry();
        second.edit(|e| {
            e.set_unprotected(fields::TITLE, "Duplicate");
            e.set_unprotected(fields::USERNAME, "second-account");
            e.set_protected(fields::PASSWORD, "second-secret");
        });
    }
    db
}

/// The root group's id. A tiny helper so [`build_nested`] reads as a chain of
/// `named_subgroup` calls without repeating the `root_mut().id()` dance.
fn db_root(db: &mut Database) -> GroupId {
    db.root_mut().id()
}

/// Add a subgroup named `name` under `parent` and return its id.
fn named_subgroup(db: &mut Database, parent: GroupId, name: &str) -> GroupId {
    let mut g = db.group_mut(parent).expect("parent group exists");
    g.add_group().edit(|g| g.name = name.to_string()).id()
}
