use std::fs::{self, File};
use std::io::{self, BufWriter, Write, Read};
use std::net::TcpStream;
use std::time::Duration;

use log::{info, warn, error};
use sha2::{Sha256, Digest};
use hex;

use crate::auth;
use crate::config::AppConfig;
use crate::db::Database;
use crate::ffmpeg;
use crate::organizer;
use crate::protocol::{self, AUTH_OK, AUTH_FAIL, RESP_OK, RESP_SKIP, RESP_NACK};

/// Обрабатывает одно входящее соединение от Android-клиента.
///
/// Фаза 1: Auth handshake (server шлёт nonce, клиент отвечает HMAC)
/// Фаза 2: Передача файла (заголовок + имя + тело)
///
/// Legacy-режим: если первый байт от клиента — тип файла (0x01..0x0D),
/// считаем что это старый клиент без auth, атрибутим файлу "legacy".
pub fn handle_connection(
    mut stream: TcpStream,
    cfg: AppConfig,
    db: Database,
) {
    let peer = stream.peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    info!("[{}] connection accepted", peer);

    // ── Фаза 1: Auth handshake ─────────────────────────────────────────
    let username = match perform_auth(&mut stream, &db, &peer) {
        AuthResult::Authenticated(user) => user,
        AuthResult::Legacy => {
            info!("[{}] legacy client detected (no auth), using 'legacy' user", peer);
            "legacy".to_string()
        }
        AuthResult::Failed(reason) => {
            warn!("[{}] auth failed: {}", peer, reason);
            return;
        }
    };

    info!("[{}] authenticated as '{}'", peer, username);

    // ── Фаза 2: Приём файла ────────────────────────────────────────────
    match process_file(&mut stream, &cfg, &db, &peer, &username) {
        Ok(action) => info!("[{}] done: {}", peer, action),
        Err(e)     => {
            error!("[{}] error: {}", peer, e);
            let _ = stream.write_all(&[RESP_NACK]);
        }
    }
}

// ── Auth handling ────────────────────────────────────────────────────────

enum AuthResult {
    Authenticated(String),
    Legacy,
    Failed(String),
}

fn perform_auth(
    stream: &mut TcpStream,
    db: &Database,
    peer: &str,
) -> AuthResult {
    // Отправляем nonce первым — клиент ждёт его для auth handshake.
    // Если legacy-клиент (старый), он не умеет auth и сразу шлёт file header,
    // тогда мы детектим это при чтении auth-пакета (первый байт != PACKET_AUTH).
    let nonce = auth::generate_nonce();
    if let Err(e) = stream.write_all(&nonce) {
        warn!("[{}] failed to send nonce: {}", peer, e);
        stream.set_read_timeout(None).ok();
        return AuthResult::Legacy;
    }
    stream.flush().ok();

    // Устанавливаем таймаут на фазу auth (5 секунд)
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    // Читаем auth пакет от клиента
    let auth_pkt = match protocol::read_auth_packet(stream) {
        Ok(p) => p,
        Err(e) => {
            warn!("[{}] auth packet read error: {}", peer, e);
            let _ = stream.write_all(&[AUTH_FAIL]);
            stream.set_read_timeout(None).ok();
            return AuthResult::Legacy;
        }
    };

    // Проверяем credentials
    match db.get_user_password_sha256(&auth_pkt.username) {
        Ok(Some(password_sha256)) => {
            let key_bytes = password_sha256.as_bytes();
            if auth::verify_auth(&auth_pkt.hmac, key_bytes, &nonce) {
                // Auth OK
                if let Err(e) = stream.write_all(&[AUTH_OK]) {
                    warn!("[{}] failed to send AUTH_OK: {}", peer, e);
                }
                stream.set_read_timeout(None).ok();
                AuthResult::Authenticated(auth_pkt.username)
            } else {
                // Wrong password
                warn!("[{}] wrong password for user '{}'", peer, auth_pkt.username);
                let _ = stream.write_all(&[AUTH_FAIL]);
                AuthResult::Failed("wrong password".to_string())
            }
        }
        Ok(None) => {
            // User not found
            warn!("[{}] user '{}' not found", peer, auth_pkt.username);
            let _ = stream.write_all(&[AUTH_FAIL]);
            AuthResult::Failed("user not found".to_string())
        }
        Err(e) => {
            error!("[{}] db error during auth: {}", peer, e);
            let _ = stream.write_all(&[AUTH_FAIL]);
            AuthResult::Failed("db error".to_string())
        }
    }
}

// ── File processing ──────────────────────────────────────────────────────

fn process_file(
    stream: &mut TcpStream,
    cfg:    &AppConfig,
    db:     &Database,
    peer:   &str,
    username: &str,
) -> Result<String, String> {

    // ── 1. Читаем заголовок ──────────────────────────────────────────────
    let header = protocol::read_header(stream)
        .map_err(|e| format!("header read error: {}", e))?;

    let sha256_hex = hex::encode(&header.sha256);
    let filename   = protocol::read_filename(stream, header.name_len)
        .map_err(|e| format!("filename read error: {}", e))?;

    info!(
        "[{}] receiving '{}' type={} size={} sha256={}... user={}",
        peer, filename,
        protocol::file_type_name(header.file_type),
        human_size(header.file_size),
        &sha256_hex[..12],
        username,
    );

    // ── 2. Дедупликация (per-user) ──────────────────────────────────────
    match db.has_file(username, &sha256_hex) {
        Ok(true) => {
            info!("[{}] file already exists for user '{}' (sha256={}...), skipping", peer, username, &sha256_hex[..12]);
            stream.write_all(&[RESP_SKIP])
                .map_err(|e| format!("send SKIP failed: {}", e))?;
            return Ok("skipped (duplicate)".to_string());
        }
        Ok(false) => {}
        Err(e) => {
            warn!("[{}] db lookup error: {}, proceeding anyway", peer, e);
        }
    }

    // ── 3. Создаём temp_dir если нужно ───────────────────────────────────
    fs::create_dir_all(&cfg.storage.temp_dir)
        .map_err(|e| format!("cannot create temp dir: {}", e))?;

    let temp_path = organizer::build_temp_path(
        &cfg.storage.temp_dir,
        &sha256_hex,
        &filename,
    );

    // ── 4. Принимаем тело файла, считаем SHA-256 на лету ─────────────────
    {
        let file = File::create(&temp_path)
            .map_err(|e| format!("cannot create temp file {:?}: {}", temp_path, e))?;
        let mut writer = BufWriter::with_capacity(64 * 1024, file);
        let mut hasher = Sha256::new();
        let mut received: u64 = 0;
        let mut chunk = vec![0u8; 65536]; // 64 KB буфер

        while received < header.file_size {
            let to_read = std::cmp::min(
                chunk.len() as u64,
                header.file_size - received,
            ) as usize;

            let n = read_chunk(stream, &mut chunk[..to_read])
                .map_err(|e| format!("read body error after {} bytes: {}", received, e))?;

            if n == 0 {
                return Err(format!("connection closed after {} / {} bytes", received, header.file_size));
            }

            writer.write_all(&chunk[..n])
                .map_err(|e| format!("write temp file error: {}", e))?;

            hasher.update(&chunk[..n]);
            received += n as u64;
        }

        writer.flush()
            .map_err(|e| format!("flush error: {}", e))?;

        // ── 5. Проверяем хеш ─────────────────────────────────────────────
        let computed = hex::encode(hasher.finalize());
        if computed != sha256_hex {
            let _ = stream.write_all(&[RESP_NACK]);
            let _ = fs::remove_file(&temp_path);
            return Err(format!(
                "hash mismatch: expected {}, got {}",
                &sha256_hex[..12], &computed[..12]
            ));
        }

        info!("[{}] hash OK ({})", peer, &sha256_hex[..12]);
    }

    // ── 6. Определяем итоговый путь (теперь с username) ──────────────────
    let output_path = organizer::build_output_path(
        &cfg.storage.media_root,
        username,
        header.file_type,
        &filename,
        header.timestamp,
    );

    // ── 7. Сжимаем через FFmpeg ───────────────────────────────────────────
    let compress_result = if protocol::is_video_type(header.file_type) {
        ffmpeg::compress_video(&cfg.ffmpeg, &temp_path, &output_path)
    } else {
        ffmpeg::compress_photo(&cfg.ffmpeg, &temp_path, &output_path)
    };

    // Удаляем временный файл в любом случае
    let _ = fs::remove_file(&temp_path);

    compress_result.map_err(|e| format!("compression failed: {}", e))?;

    // ── 8. Записываем в БД ────────────────────────────────────────────────
    db.insert_file(
        username,
        &sha256_hex,
        output_path.to_str().unwrap_or(""),
        header.file_type,
        &filename,
        header.timestamp,
    ).map_err(|e| format!("db insert error: {}", e))?;

    // ── 9. Отправляем ACK ─────────────────────────────────────────────────
    stream.write_all(&[RESP_OK])
        .map_err(|e| format!("send ACK failed: {}", e))?;

    Ok(format!(
        "saved to {:?}",
        output_path.file_name().unwrap_or_default()
    ))
}

fn read_chunk(stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    stream.read(buf)
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{} KB", bytes / 1024)
    }
}
