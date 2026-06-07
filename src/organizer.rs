use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use crate::protocol;

/// Строит итоговый путь файла:
///   {media_root}/{username}/YYYY/MM/DD/{stem}_{timestamp}.{ext}
pub fn build_output_path(
    media_root:    &str,
    username:      &str,
    file_type:     u8,
    original_name: &str,
    timestamp:     i64,
) -> PathBuf {
    let ts = if timestamp > 0 {
        timestamp as u64
    } else {
        std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };

    let (year, month, day) = timestamp_to_ymd(ts);
    let ext = protocol::output_extension(file_type);

    let stem = PathBuf::from(original_name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file")
        .to_string();

    let safe_stem: String = stem.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect();

    // /data/PV/{username}/YYYY/MM/DD/
    let base_dir = PathBuf::from(media_root)
        .join(sanitize_username(username))
        .join(format!("{:04}", year))
        .join(format!("{:02}", month))
        .join(format!("{:02}", day));

    let mut path = base_dir.join(format!("{}_{}.{}", safe_stem, ts, ext));

    // Коллизия имён — добавляем счётчик
    let mut counter = 0u32;
    while path.exists() && counter < 999 {
        counter += 1;
        path = base_dir.join(format!("{}_{}_{}.{}", safe_stem, ts, counter, ext));
    }

    path
}

/// Sanitizes username for use in filesystem paths.
/// Replaces any dangerous characters with underscores.
fn sanitize_username(username: &str) -> String {
    username.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect()
}

/// Временный путь для приёма файла
pub fn build_temp_path(temp_dir: &str, sha256_hex: &str, original_name: &str) -> PathBuf {
    let prefix = &sha256_hex[..16];
    let safe_name: String = original_name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' { c } else { '_' })
        .collect();
    PathBuf::from(temp_dir).join(format!("{}_{}", prefix, safe_name))
}

/// UNIX timestamp → (год, месяц, день)
fn timestamp_to_ymd(ts: u64) -> (u32, u32, u32) {
    let days = ts / 86400;
    let z    = days + 719468;
    let era  = z / 146097;
    let doe  = z - era * 146097;
    let yoe  = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    let y    = yoe + era * 400;
    let doy  = doe - (365*yoe + yoe/4 - yoe/100);
    let mp   = (5*doy + 2) / 153;
    let d    = doy - (153*mp + 2)/5 + 1;
    let m    = if mp < 10 { mp + 3 } else { mp - 9 };
    let y    = if m <= 2  { y + 1  } else { y };
    (y as u32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{FILE_TYPE_VIDEO, FILE_TYPE_PNG, FILE_TYPE_MKV};

    #[test]
    fn test_per_user_path() {
        let path = build_output_path("/data/PV", "alice", FILE_TYPE_VIDEO, "test.mp4", 1748044800);
        let s = path.to_str().unwrap();
        assert!(s.starts_with("/data/PV/alice/2025/05/24/"), "wrong path: {}", s);
        assert_eq!(s.matches("2025").count(), 1, "year duplicated: {}", s);
    }

    #[test]
    fn test_png_path() {
        let path = build_output_path("/data/PV", "bob", FILE_TYPE_PNG, "screenshot.png", 1748044800);
        let s = path.to_str().unwrap();
        assert!(s.starts_with("/data/PV/bob/2025/05/24/"), "wrong path: {}", s);
        assert!(s.ends_with(".png"), "png should keep .png extension: {}", s);
    }

    #[test]
    fn test_mkv_becomes_mp4() {
        let path = build_output_path("/data/PV", "carol", FILE_TYPE_MKV, "video.mkv", 1748044800);
        let s = path.to_str().unwrap();
        assert!(s.ends_with(".mp4"), "mkv should become .mp4: {}", s);
    }

    #[test]
    fn test_username_sanitization() {
        let path = build_output_path("/data/PV", "../evil", FILE_TYPE_VIDEO, "test.mp4", 1748044800);
        let s = path.to_str().unwrap();
        assert!(s.contains("__evil"), "path traversal not prevented: {}", s);
    }

    #[test]
    fn test_timestamp_to_ymd() {
        let (y, m, d) = timestamp_to_ymd(1748044800);
        assert_eq!((y, m, d), (2025, 5, 24));
    }
}
