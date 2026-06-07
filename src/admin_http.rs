use log::{info, warn, error};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read as IoRead;
use std::thread;
use tiny_http::{Server, Request, Response, Header, StatusCode};

use crate::config::AdminConfig;
use crate::db::Database;

/// Запускает HTTP-сервер (админка + галерея) в отдельном потоке.
pub fn start_admin_server(
    cfg: AdminConfig,
    db: Database,
    media_root: String,
) {
    let bind_addr = cfg.http_bind.clone();
    let token = cfg.api_token.clone();

    thread::spawn(move || {
        let server = match Server::http(&bind_addr) {
            Ok(s) => s,
            Err(e) => {
                error!("cannot start admin HTTP server on {}: {}", bind_addr, e);
                return;
            }
        };

        info!("admin HTTP server listening on {}", bind_addr);

        for request in server.incoming_requests() {
            if let Err(e) = handle_request(request, &token, &db, &media_root) {
                warn!("request error: {}", e);
            }
        }
    });
}

fn check_auth(request: &Request, token: &str) -> bool {
    let auth_header = request.headers().iter()
        .find(|h| {
            h.field.as_str().as_str() == "Authorization"
                || h.field.as_str().as_str() == "authorization"
        });

    match auth_header {
        Some(h) => {
            let value = h.value.as_str();
            value.starts_with("Bearer ") && &value[7..] == token
        }
        None => false,
    }
}

fn json_response(body: String, status: StatusCode) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body)
        .with_status_code(status)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
}

fn handle_request(
    request: Request,
    token: &str,
    db: &Database,
    media_root: &str,
) -> Result<(), String> {
    if !check_auth(&request, token) {
        return request.respond(json_response(
            "{\"error\": \"Unauthorized\"}".to_string(),
            StatusCode(401),
        )).map_err(|e| e.to_string());
    }

    let url = request.url().to_string();
    let method = request.method().to_string();

    // ── Admin endpoints ──────────────────────────────────────────────
    match (method.as_str(), url.as_str()) {
        ("POST", _) if url == "/api/users" => {
            return handle_create_user(request, db);
        }
        ("GET", _) if url == "/api/users" => {
            return handle_list_users(request, db);
        }
        ("DELETE", _) if url.starts_with("/api/users/") => {
            let username = &url["/api/users/".len()..];
            return handle_delete_user(request, db, username);
        }
        _ => {}
    }

    // ── Gallery endpoints ────────────────────────────────────────────
    // GET /api/gallery/{username}?page=0&limit=50
    if method == "GET" && url.starts_with("/api/gallery/") {
        let parts: Vec<&str> = url.trim_start_matches("/api/gallery/").split('?').collect();
        let username = parts[0];
        if username.is_empty() || username.contains('/') {
            return request.respond(json_response(
                "{\"error\": \"Invalid username\"}".to_string(),
                StatusCode(400),
            )).map_err(|e| e.to_string());
        }

        let page: u32 = url_param(&url, "page").unwrap_or(0);
        let limit: u32 = url_param(&url, "limit").unwrap_or(50);

        return handle_list_gallery(request, db, username, page, limit);
    }

    // GET /api/gallery/{username}/storage
    if method == "GET" && url.starts_with("/api/gallery/") && url.ends_with("/storage") {
        let username = url.trim_start_matches("/api/gallery/").trim_end_matches("/storage");
        if username.is_empty() || username.contains('/') {
            return request.respond(json_response(
                "{\"error\": \"Invalid username\"}".to_string(),
                StatusCode(400),
            )).map_err(|e| e.to_string());
        }
        return handle_storage_usage(request, db, username, media_root);
    }

    // GET /api/gallery/{username}/download/{sha256}
    if method == "GET" && url.starts_with("/api/gallery/") && url.contains("/download/") {
        let rest = url.trim_start_matches("/api/gallery/");
        let parts: Vec<&str> = rest.splitn(2, "/download/").collect();
        if parts.len() == 2 {
            let username = parts[0];
            let sha256 = parts[1];
            if !username.is_empty() && sha256.len() == 64 {
                return handle_download_file(request, db, username, sha256, media_root);
            }
        }
    }

    // ── Fallback ─────────────────────────────────────────────────────
    request.respond(json_response(
        "{\"error\": \"Not Found\"}".to_string(),
        StatusCode(404),
    )).map_err(|e| e.to_string())
}

fn url_param(url: &str, key: &str) -> Option<u32> {
    if let Some(query_start) = url.find('?') {
        let query = &url[query_start + 1..];
        for param in query.split('&') {
            if let Some((k, v)) = param.split_once('=') {
                if k == key {
                    return v.parse().ok();
                }
            }
        }
    }
    None
}

// ── Gallery handlers ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct GalleryItem {
    sha256: String,
    original_name: String,
    file_type: String,
    shot_at: i64,
    received_at: i64,
    download_url: String,
}

fn handle_list_gallery(
    request: Request,
    db: &Database,
    username: &str,
    page: u32,
    limit: u32,
) -> Result<(), String> {
    match db.list_files_for_user(username, page, limit) {
        Ok(files) => {
            let items: Vec<GalleryItem> = files.iter().map(|f| {
                GalleryItem {
                    sha256: f.sha256.clone(),
                    original_name: f.original_name.clone(),
                    file_type: if f.file_type <= 2 { "photo" } else { "video" }.to_string(),
                    shot_at: f.shot_at,
                    received_at: f.received_at,
                    download_url: format!("/api/gallery/{}/download/{}", username, f.sha256),
                }
            }).collect();

            // Total count for pagination
            let total = db.get_total_count(username).unwrap_or(0);
            let body = serde_json::to_string(&serde_json::json!({
                "total": total,
                "page": page,
                "limit": limit,
                "files": items,
            })).unwrap_or_else(|_| "[]".to_string());

            request.respond(json_response(body, StatusCode(200)))
                .map_err(|e| e.to_string())
        }
        Err(e) => {
            request.respond(json_response(
                format!("{{\"error\": \"{}\"}}", e),
                StatusCode(500),
            )).map_err(|e| e.to_string())
        }
    }
}

#[derive(Serialize)]
struct StorageResponse {
    used_bytes: u64,
    used_human: String,
    file_count: i64,
}

fn handle_storage_usage(
    request: Request,
    db: &Database,
    username: &str,
    media_root: &str,
) -> Result<(), String> {
    match db.get_storage_usage(username, media_root) {
        Ok(usage) => {
            let body = serde_json::to_string(&StorageResponse {
                used_bytes: usage.used_bytes,
                used_human: human_size(usage.used_bytes),
                file_count: usage.file_count,
            }).unwrap_or_else(|_| "{}".to_string());
            request.respond(json_response(body, StatusCode(200)))
                .map_err(|e| e.to_string())
        }
        Err(e) => {
            request.respond(json_response(
                format!("{{\"error\": \"{}\"}}", e),
                StatusCode(500),
            )).map_err(|e| e.to_string())
        }
    }
}

fn handle_download_file(
    request: Request,
    db: &Database,
    username: &str,
    sha256: &str,
    _media_root: &str,
) -> Result<(), String> {
    match db.get_file_by_sha256(username, sha256) {
        Ok(Some(file_info)) => {
            let file_path = std::path::Path::new(&file_info.file_path);
            if !file_path.exists() {
                return request.respond(json_response(
                    "{\"error\": \"File not found on disk\"}".to_string(),
                    StatusCode(404),
                )).map_err(|e| e.to_string());
            }

            let mut file = File::open(file_path).map_err(|e| format!("open file: {}", e))?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).map_err(|e| format!("read file: {}", e))?;

            let mime = match std::path::Path::new(&file_info.file_path)
                .extension().and_then(|e| e.to_str()) {
                Some("mp4") => "video/mp4",
                Some("jpg") | Some("jpeg") => "image/jpeg",
                Some("png") => "image/png",
                Some("webp") => "image/webp",
                Some("gif") => "image/gif",
                _ => "application/octet-stream",
            };

            let resp = Response::from_data(buf)
                .with_status_code(StatusCode(200))
                .with_header(Header::from_bytes("Content-Type", mime).unwrap())
                .with_header(Header::from_bytes(
                    "Content-Disposition",
                    format!("attachment; filename=\"{}\"", file_info.original_name),
                ).unwrap());

            request.respond(resp).map_err(|e| e.to_string())
        }
        Ok(None) => {
            request.respond(json_response(
                "{\"error\": \"File not found\"}".to_string(),
                StatusCode(404),
            )).map_err(|e| e.to_string())
        }
        Err(e) => {
            request.respond(json_response(
                format!("{{\"error\": \"{}\"}}", e),
                StatusCode(500),
            )).map_err(|e| e.to_string())
        }
    }
}

// ── Admin handlers ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct UserResponse {
    username: String,
    created_at: i64,
}

fn handle_create_user(
    mut request: Request,
    db: &Database,
) -> Result<(), String> {
    let mut buf = Vec::new();
    request.as_reader().read_to_end(&mut buf)
        .map_err(|e| format!("read body: {}", e))?;

    let req: CreateUserRequest = serde_json::from_slice(&buf)
        .map_err(|e| format!("parse JSON: {}", e))?;

    if req.username.len() < 1 || req.username.len() > 32 {
        return request.respond(json_response(
            "{\"error\": \"Username must be 1-32 chars\"}".to_string(),
            StatusCode(400),
        )).map_err(|e| e.to_string());
    }

    if !req.username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return request.respond(json_response(
            "{\"error\": \"Username: only a-z, 0-9, _, -\"}".to_string(),
            StatusCode(400),
        )).map_err(|e| e.to_string());
    }

    if req.password.len() < 4 {
        return request.respond(json_response(
            "{\"error\": \"Password too short (min 4 chars)\"}".to_string(),
            StatusCode(400),
        )).map_err(|e| e.to_string());
    }

    match db.create_user(&req.username, &req.password) {
        Ok(()) => {
            info!("user created: {}", req.username);
            request.respond(json_response(
                format!("{{\"ok\": true, \"username\": \"{}\"}}", req.username),
                StatusCode(200),
            )).map_err(|e| e.to_string())
        }
        Err(e) => {
            warn!("create user failed: {}", e);
            request.respond(json_response(
                format!("{{\"ok\": false, \"error\": \"{}\"}}", e),
                StatusCode(409),
            )).map_err(|e| e.to_string())
        }
    }
}

fn handle_list_users(
    request: Request,
    db: &Database,
) -> Result<(), String> {
    match db.list_users() {
        Ok(users) => {
            let resp_users: Vec<UserResponse> = users
                .into_iter()
                .map(|(u, c)| UserResponse { username: u, created_at: c })
                .collect();
            let body = serde_json::to_string(&resp_users)
                .unwrap_or_else(|_| "[]".to_string());
            request.respond(json_response(body, StatusCode(200)))
                .map_err(|e| e.to_string())
        }
        Err(e) => {
            request.respond(json_response(
                format!("{{\"error\": \"{}\"}}", e),
                StatusCode(500),
            )).map_err(|e| e.to_string())
        }
    }
}

fn handle_delete_user(
    request: Request,
    db: &Database,
    username: &str,
) -> Result<(), String> {
    match db.delete_user(username) {
        Ok(n) if n > 0 => {
            info!("user deleted: {}", username);
            request.respond(json_response(
                format!("{{\"ok\": true, \"deleted\": {}}}", n),
                StatusCode(200),
            )).map_err(|e| e.to_string())
        }
        Ok(_) => {
            request.respond(json_response(
                "{\"ok\": false, \"error\": \"user not found\"}".to_string(),
                StatusCode(404),
            )).map_err(|e| e.to_string())
        }
        Err(e) => {
            request.respond(json_response(
                format!("{{\"ok\": false, \"error\": \"{}\"}}", e),
                StatusCode(500),
            )).map_err(|e| e.to_string())
        }
    }
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
