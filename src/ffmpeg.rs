use std::path::Path;
use std::process::Command;
use log::{info, error};

use crate::config::FfmpegConfig;

/// Сжимает видеофайл через FFmpeg.
///
/// Обрабатывает: mp4, mkv, mov, 3gp, mpeg, webm → выход всегда .mp4
pub fn compress_video(
    cfg: &FfmpegConfig,
    input: &Path,
    output: &Path,
) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!("cannot create output dir {:?}: {}", parent, e)
        })?;
    }

    // Масштабирование если нужно
    let vf_filter = if cfg.video_max_width > 0 {
        format!(
            "scale='if(gt(iw,{max}),{max},-2)':'if(gt(ih,{max}),{max},-2)',\
             scale=trunc(iw/2)*2:trunc(ih/2)*2",
            max = cfg.video_max_width
        )
    } else {
        "scale=trunc(iw/2)*2:trunc(ih/2)*2".to_string()
    };

    // Определяем входной формат по расширению для правильной обработки
    let input_ext = input.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Для 3gp, webm, mkv и других контейнеров ffmpeg автоматически
    // определяет кодеки, поэтому дополнительные флаги не нужны
    info!(
        "compressing video: {:?} ({}) -> {:?} (codec={}, crf={}, preset={})",
        input, input_ext, output, cfg.video_codec, cfg.video_crf, cfg.video_preset
    );

    let status = Command::new(&cfg.ffmpeg_path)
        .args([
            "-y",
            "-i", input.to_str().unwrap(),
            "-c:v", &cfg.video_codec,
            "-crf", &cfg.video_crf.to_string(),
            "-preset", &cfg.video_preset,
            "-vf", &vf_filter,
            "-c:a", "aac",
            "-b:a", "128k",
            "-movflags", "+faststart",
            "-map_metadata", "0",
            output.to_str().unwrap(),
        ])
        .status()
        .map_err(|e| format!("failed to spawn ffmpeg: {}", e))?;

    if status.success() {
        let orig_size = std::fs::metadata(input).map(|m| m.len()).unwrap_or(0);
        let new_size  = std::fs::metadata(output).map(|m| m.len()).unwrap_or(0);
        info!(
            "video compressed: {:.1} MB -> {:.1} MB ({:.0}%)",
            orig_size as f64 / 1_048_576.0,
            new_size  as f64 / 1_048_576.0,
            if orig_size > 0 { new_size as f64 / orig_size as f64 * 100.0 } else { 0.0 }
        );
        Ok(())
    } else {
        error!("ffmpeg exited with: {:?}", status.code());
        Err(format!("ffmpeg failed with exit code {:?}", status.code()))
    }
}

/// Сжимает фото через FFmpeg.
///
/// JPEG: перекодирует с заданным качеством (q:v)
/// Остальные форматы: конвертирует в JPEG (PNG, WebP, HEIC, GIF, BMP, RAW)
/// Для GIF берётся первый кадр.
pub fn compress_photo(
    cfg: &FfmpegConfig,
    input: &Path,
    output: &Path,
) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!("cannot create output dir {:?}: {}", parent, e)
        })?;
    }

    // Всегда конвертируем фото в JPEG. Android может ошибочно маппить
    // MIME-типы (напр. HEIC/MJPEG как image/png), но FFmpeg по содержимому
    // разберётся. -frames:v 1 гарантирует один кадр даже из видео/анимаций.
    let qv = 2 + (100 - cfg.photo_quality as u32) * 29 / 100;

    info!(
        "compressing photo: {:?} -> {:?} (quality={})",
        input, output, cfg.photo_quality
    );

    let args = vec![
        "-y".to_string(),
        "-i".to_string(), input.to_str().unwrap().to_string(),
        "-q:v".to_string(), qv.to_string(),
        "-frames:v".to_string(), "1".to_string(),
        "-map_metadata".to_string(), "0".to_string(),
        output.to_str().unwrap().to_string(),
    ];

    let status = Command::new(&cfg.ffmpeg_path)
        .args(&args)
        .status()
        .map_err(|e| format!("failed to spawn ffmpeg: {}", e))?;

    if status.success() {
        let orig_size = std::fs::metadata(input).map(|m| m.len()).unwrap_or(0);
        let new_size  = std::fs::metadata(output).map(|m| m.len()).unwrap_or(0);
        info!(
            "photo compressed: {:.1} KB -> {:.1} KB ({:.0}%)",
            orig_size as f64 / 1024.0,
            new_size  as f64 / 1024.0,
            if orig_size > 0 { new_size as f64 / orig_size as f64 * 100.0 } else { 0.0 }
        );
        Ok(())
    } else {
        Err(format!("ffmpeg failed with exit code {:?}", status.code()))
    }
}

/// Проверяет что ffmpeg доступен и выводит версию в лог
pub fn check_ffmpeg(path: &str) -> Result<(), String> {
    let output = Command::new(path)
        .arg("-version")
        .output()
        .map_err(|e| format!("cannot run ffmpeg at '{}': {}", path, e))?;

    if output.status.success() {
        let version_line = String::from_utf8_lossy(&output.stdout);
        let first_line = version_line.lines().next().unwrap_or("unknown");
        info!("ffmpeg found: {}", first_line);
        Ok(())
    } else {
        Err(format!("ffmpeg at '{}' returned error", path))
    }
}
