mod admin_http;
mod auth;
mod config;
mod db;
mod ffmpeg;
mod handler;
mod organizer;
mod protocol;

use std::env;
use std::net::TcpListener;
use std::process;
use std::thread;

use log::{info, error};

fn main() {
    // ── Логирование ───────────────────────────────────────────────────────
    if env::var("RUST_LOG").is_err() {
        unsafe { env::set_var("RUST_LOG", "info") };
    }
    env_logger::init();

    // ── Конфиг ────────────────────────────────────────────────────────────
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    info!("loading config from '{}'", config_path);

    let cfg = match config::AppConfig::load(&config_path) {
        Ok(c)  => c,
        Err(e) => {
            error!("failed to load config: {}", e);
            process::exit(1);
        }
    };

    // ── Проверка FFmpeg ───────────────────────────────────────────────────
    if let Err(e) = ffmpeg::check_ffmpeg(&cfg.ffmpeg.ffmpeg_path) {
        error!("{}", e);
        error!("install ffmpeg: sudo pacman -S ffmpeg");
        process::exit(1);
    }

    // ── База данных ───────────────────────────────────────────────────────
    let db = match db::Database::open(&cfg.database.db_path) {
        Ok(d)  => d,
        Err(e) => {
            error!("failed to open database '{}': {}", cfg.database.db_path, e);
            process::exit(1);
        }
    };

    // ── Legacy migration ─────────────────────────────────────────────────
    match db.migrate_legacy() {
        Ok(0) => info!("no legacy files to migrate"),
        Ok(n) => info!("migrated {} legacy files to 'legacy' user", n),
        Err(e) => error!("legacy migration error: {}", e),
    }

    match db.count() {
        Ok(n)  => info!("database ready: {} files indexed", n),
        Err(e) => error!("db count error: {}", e),
    }

    // ── Admin HTTP server ────────────────────────────────────────────────
    if let Some(admin_cfg) = cfg.admin_config() {
        info!("starting admin HTTP server on {}", admin_cfg.http_bind);
        admin_http::start_admin_server(admin_cfg.clone(), db.clone(), cfg.storage.media_root.clone());
    } else {
        info!("admin HTTP server not configured (no [admin] section in config)");
    }

    // ── TCP Listener ──────────────────────────────────────────────────────
    let bind_addr = cfg.bind_addr();
    let listener  = match TcpListener::bind(&bind_addr) {
        Ok(l)  => l,
        Err(e) => {
            error!("cannot bind to {}: {}", bind_addr, e);
            process::exit(1);
        }
    };

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("  mediaserver listening on {}", bind_addr);
    info!("  media root : {}", cfg.storage.media_root);
    info!("  temp dir   : {}", cfg.storage.temp_dir);
    info!("  database   : {}", cfg.database.db_path);
    info!("  codec      : {} / crf={}", cfg.ffmpeg.video_codec, cfg.ffmpeg.video_crf);
    if cfg.admin_config().is_some() {
        info!("  admin HTTP: {}", cfg.admin_config().unwrap().http_bind);
    }
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let cfg_clone = cfg.clone();
                let db_clone  = db.clone();

                thread::spawn(move || {
                    handler::handle_connection(stream, cfg_clone, db_clone);
                });
            }
            Err(e) => {
                error!("accept error: {}", e);
            }
        }
    }
}
