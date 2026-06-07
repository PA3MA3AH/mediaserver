use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub media_root: String,
    pub temp_dir: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FfmpegConfig {
    pub ffmpeg_path: String,
    pub video_crf: u8,
    pub video_codec: String,
    pub video_preset: String,
    pub video_max_width: u32,
    pub photo_quality: u8,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub db_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    pub http_bind: String,
    pub api_token: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server:   ServerConfig,
    pub storage:  StorageConfig,
    pub ffmpeg:   FfmpegConfig,
    pub database: DatabaseConfig,
    pub admin:    Option<AdminConfig>,
}

impl AppConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = fs::read_to_string(&path).map_err(|e| {
            format!("cannot read config file {:?}: {}", path.as_ref(), e)
        })?;

        toml::from_str(&content).map_err(|e| {
            format!("failed to parse config: {}", e)
        })
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.server.bind_address, self.server.port)
    }

    /// Возвращает конфиг админки или None если не настроен
    pub fn admin_config(&self) -> Option<&AdminConfig> {
        self.admin.as_ref()
    }
}
