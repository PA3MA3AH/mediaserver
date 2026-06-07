use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use hex;
use rusqlite::{Connection, params, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Arc, Mutex};

type DbResult<T> = std::result::Result<T, String>;

/// Обёртка над SQLite, безопасная для многопоточности (Arc<Mutex<>>)
#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

fn map_db_err(e: rusqlite::Error) -> String {
    format!("db error: {}", e)
}

impl Database {
    /// Открывает (или создаёт) БД и инициализирует таблицы
    pub fn open<P: AsRef<Path>>(path: P) -> DbResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let conn = Connection::open(&path).map_err(map_db_err)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;").map_err(map_db_err)?;
        conn.execute_batch("PRAGMA synchronous=NORMAL;").map_err(map_db_err)?;

        // Check if old DB exists and lacks the username column
        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='files'",
            [],
            |row| row.get::<_, i64>(0),
        ).map(|c| c > 0).unwrap_or(false);

        if table_exists {
            let has_username: bool = conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('files') WHERE name='username'",
                [],
                |row| row.get::<_, i64>(0),
            ).map(|c| c > 0).unwrap_or(false);

            if !has_username {
                conn.execute(
                    "ALTER TABLE files ADD COLUMN username TEXT NOT NULL DEFAULT 'legacy'",
                    [],
                ).map_err(map_db_err)?;
            }
        }

        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS files (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256      TEXT    NOT NULL UNIQUE,
                file_path   TEXT    NOT NULL,
                file_type   INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                shot_at     INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                username    TEXT    NOT NULL DEFAULT 'legacy'
            );
            CREATE INDEX IF NOT EXISTS idx_sha256   ON files(sha256);
            CREATE INDEX IF NOT EXISTS idx_shot_at  ON files(shot_at);
            CREATE INDEX IF NOT EXISTS idx_username ON files(username);
        ").map_err(map_db_err)?;

        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT    NOT NULL UNIQUE,
                password_hash   TEXT    NOT NULL,
                password_sha256 TEXT    NOT NULL,
                created_at      INTEGER NOT NULL
            );
        ").map_err(map_db_err)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    // ── User management ────────────────────────────────────────────────

    pub fn create_user(&self, username: &str, password: &str) -> DbResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| format!("argon2 error: {}", e))?
            .to_string();

        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let password_sha256 = hex::encode(hasher.finalize());

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (username, password_hash, password_sha256, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![username, password_hash, password_sha256, now],
        ).map_err(map_db_err)?;
        Ok(())
    }

    pub fn verify_password(&self, username: &str, password: &str) -> DbResult<bool> {
        let conn = self.conn.lock().unwrap();
        let hash: Option<String> = conn.query_row(
            "SELECT password_hash FROM users WHERE username = ?1",
            params![username],
            |row| row.get(0),
        ).optional().map_err(map_db_err)?;

        match hash {
            Some(hash_str) => {
                let parsed_hash = PasswordHash::new(&hash_str)
                    .map_err(|e| format!("parse hash error: {}", e))?;
                Ok(Argon2::default()
                    .verify_password(password.as_bytes(), &parsed_hash)
                    .is_ok())
            }
            None => Ok(false),
        }
    }

    pub fn get_user_password_sha256(&self, username: &str) -> DbResult<Option<String>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT password_sha256 FROM users WHERE username = ?1",
            params![username],
            |row| row.get(0),
        ).optional().map_err(map_db_err)
    }

    pub fn list_users(&self) -> DbResult<Vec<(String, i64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT username, created_at FROM users ORDER BY username")
            .map_err(map_db_err)?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?))
        }).map_err(map_db_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| format!("row error: {}", e))
    }

    pub fn delete_user(&self, username: &str) -> DbResult<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM users WHERE username = ?1",
            params![username],
        ).map_err(map_db_err)
    }

    // ── File management (per-user) ─────────────────────────────────────

    pub fn has_file(&self, username: &str, sha256_hex: &str) -> DbResult<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM files WHERE sha256 = ?1 AND username = ?2",
            params![sha256_hex, username],
            |row| row.get(0),
        ).map_err(map_db_err)?;
        Ok(count > 0)
    }

    pub fn insert_file(
        &self,
        username:      &str,
        sha256_hex:    &str,
        file_path:     &str,
        file_type:     u8,
        original_name: &str,
        shot_at:       i64,
    ) -> DbResult<()> {
        let conn = self.conn.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        conn.execute(
            "INSERT OR IGNORE INTO files
             (sha256, file_path, file_type, original_name, shot_at, received_at, username)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![sha256_hex, file_path, file_type as i32, original_name, shot_at, now, username],
        ).map_err(map_db_err)?;
        Ok(())
    }

    pub fn count_for_user(&self, username: &str) -> DbResult<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM files WHERE username = ?1",
            params![username],
            |row| row.get(0),
        ).map_err(map_db_err)
    }

    pub fn count(&self) -> DbResult<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
            .map_err(map_db_err)
    }

    pub fn migrate_legacy(&self) -> DbResult<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE files SET username = 'legacy' WHERE username = '' OR username IS NULL",
            [],
        ).map_err(map_db_err)
    }

    // ── Gallery queries ───────────────────────────────────────────────

    pub fn list_files_for_user(
        &self,
        username: &str,
        page: u32,
        limit: u32,
    ) -> DbResult<Vec<FileInfo>> {
        let conn = self.conn.lock().unwrap();
        let offset = page * limit;
        let mut stmt = conn.prepare(
            "SELECT sha256, file_path, file_type, original_name, shot_at, received_at, id
             FROM files
             WHERE username = ?1
             ORDER BY shot_at DESC
             LIMIT ?2 OFFSET ?3"
        ).map_err(map_db_err)?;

        let rows = stmt.query_map(
            params![username, limit, offset],
            |row| {
                Ok(FileInfo {
                    sha256: row.get(0)?,
                    file_path: row.get(1)?,
                    file_type: row.get(2)?,
                    original_name: row.get(3)?,
                    shot_at: row.get(4)?,
                    received_at: row.get(5)?,
                    id: row.get(6)?,
                })
            }
        ).map_err(map_db_err)?;

        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| format!("row error: {}", e))
    }

    pub fn get_file_by_sha256(&self, username: &str, sha256_hex: &str) -> DbResult<Option<FileInfo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT sha256, file_path, file_type, original_name, shot_at, received_at, id
             FROM files
             WHERE sha256 = ?1 AND username = ?2"
        ).map_err(map_db_err)?;

        stmt.query_row(params![sha256_hex, username], |row| {
            Ok(FileInfo {
                sha256: row.get(0)?,
                file_path: row.get(1)?,
                file_type: row.get(2)?,
                original_name: row.get(3)?,
                shot_at: row.get(4)?,
                received_at: row.get(5)?,
                id: row.get(6)?,
            })
        }).optional().map_err(map_db_err)
    }

    pub fn get_total_count(&self, username: &str) -> DbResult<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM files WHERE username = ?1",
            params![username],
            |row| row.get(0),
        ).map_err(map_db_err)
    }

    pub fn get_storage_usage(&self, username: &str, media_root: &str) -> DbResult<StorageUsage> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM files WHERE username = ?1",
            params![username],
            |row| row.get(0),
        ).map_err(map_db_err)?;

        // Calculate folder size on disk
        let user_dir = std::path::Path::new(media_root).join(sanitize_username(username));
        let total_bytes = if user_dir.exists() {
            dir_size(&user_dir).unwrap_or(0)
        } else {
            0
        };

        Ok(StorageUsage {
            used_bytes: total_bytes,
            file_count: count,
        })
    }
}

#[derive(Debug)]
pub struct FileInfo {
    pub sha256: String,
    pub file_path: String,
    pub file_type: i32,
    pub original_name: String,
    pub shot_at: i64,
    pub received_at: i64,
    pub id: i64,
}

#[derive(Debug)]
pub struct StorageUsage {
    pub used_bytes: u64,
    pub file_count: i64,
}

fn dir_size(path: &std::path::Path) -> std::io::Result<u64> {
    let mut total = 0;
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                total += entry.metadata()?.len();
            } else if path.is_dir() {
                total += dir_size(&path)?;
            }
        }
    }
    Ok(total)
}

fn sanitize_username(username: &str) -> String {
    username.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect()
}
