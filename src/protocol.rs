/// Бинарный протокол обмена между Android-клиентом и Rust-сервером.
///
/// После установки соединения сервер шлёт 32-байтовый nonce.
/// Клиент отвечает auth-пакетом:
///   [1B: 0x10][4B: username_len][username][32B: HMAC-SHA256]
/// Сервер отвечает 1 байтом: 0x01=OK, 0x00=FAIL.
/// После OK начинается передача файла (старый заголовок 53B + имя + тело).
///
/// Если первый байт от клиента не 0x10 — legacy-режим (без auth).

use std::io::{self, Read};
use std::net::TcpStream;

// ── Auth пакеты ────────────────────────────────────────────────────────
pub const PACKET_AUTH: u8  = 0x10;
pub const AUTH_OK: u8      = 0x01;
pub const AUTH_FAIL: u8    = 0x00;

// ── Типы файлов ────────────────────────────────────────────────────────
pub const FILE_TYPE_VIDEO: u8  = 0x01;
pub const FILE_TYPE_PHOTO: u8  = 0x02;
pub const FILE_TYPE_PNG: u8    = 0x03;
pub const FILE_TYPE_WEBP: u8   = 0x04;
pub const FILE_TYPE_HEIC: u8   = 0x05;
pub const FILE_TYPE_GIF: u8    = 0x06;
pub const FILE_TYPE_BMP: u8    = 0x07;
pub const FILE_TYPE_MKV: u8    = 0x08;
pub const FILE_TYPE_MOV: u8    = 0x09;
pub const FILE_TYPE_MPEG: u8   = 0x0A;
pub const FILE_TYPE_3GP: u8    = 0x0B;
pub const FILE_TYPE_RAW: u8    = 0x0C;
pub const FILE_TYPE_WEBM: u8   = 0x0D;

// ── Ответы сервера (для передачи файлов) ───────────────────────────────
pub const RESP_OK: u8   = 0xAA;
pub const RESP_SKIP: u8 = 0xBB;
pub const RESP_NACK: u8 = 0xFF;

pub const HEADER_SIZE: usize = 53;

/// Проверяет валидный ли это байт типа файла
pub fn is_valid_file_type(t: u8) -> bool {
    matches!(t,
        FILE_TYPE_VIDEO | FILE_TYPE_PHOTO | FILE_TYPE_PNG | FILE_TYPE_WEBP
        | FILE_TYPE_HEIC | FILE_TYPE_GIF | FILE_TYPE_BMP | FILE_TYPE_MKV
        | FILE_TYPE_MOV | FILE_TYPE_MPEG | FILE_TYPE_3GP | FILE_TYPE_RAW
        | FILE_TYPE_WEBM
    )
}

/// Возвращает строковое описание типа файла для логов
pub fn file_type_name(t: u8) -> &'static str {
    match t {
        FILE_TYPE_VIDEO  => "video",
        FILE_TYPE_PHOTO  => "photo",
        FILE_TYPE_PNG    => "png",
        FILE_TYPE_WEBP   => "webp",
        FILE_TYPE_HEIC   => "heic",
        FILE_TYPE_GIF    => "gif",
        FILE_TYPE_BMP    => "bmp",
        FILE_TYPE_MKV    => "mkv",
        FILE_TYPE_MOV    => "mov",
        FILE_TYPE_MPEG   => "mpeg",
        FILE_TYPE_3GP    => "3gp",
        FILE_TYPE_RAW    => "raw",
        FILE_TYPE_WEBM   => "webm",
        _                => "unknown",
    }
}

/// Определяет, является ли тип фото-типом (обрабатывается как изображение)
pub fn is_photo_type(t: u8) -> bool {
    matches!(t,
        FILE_TYPE_PHOTO | FILE_TYPE_PNG | FILE_TYPE_WEBP | FILE_TYPE_HEIC
        | FILE_TYPE_GIF | FILE_TYPE_BMP | FILE_TYPE_RAW
    )
}

/// Определяет, является ли тип видео-типом
pub fn is_video_type(t: u8) -> bool {
    matches!(t, FILE_TYPE_VIDEO | FILE_TYPE_MKV | FILE_TYPE_MOV | FILE_TYPE_MPEG | FILE_TYPE_3GP | FILE_TYPE_WEBM)
}

/// Определяет расширение выходного файла
pub fn output_extension(file_type: u8) -> &'static str {
    match file_type {
        FILE_TYPE_VIDEO | FILE_TYPE_MKV | FILE_TYPE_MOV | FILE_TYPE_MPEG | FILE_TYPE_3GP | FILE_TYPE_WEBM => "mp4",
        FILE_TYPE_PHOTO => "jpg",
        FILE_TYPE_PNG => "png",
        FILE_TYPE_WEBP => "webp",
        FILE_TYPE_GIF => "gif",
        FILE_TYPE_BMP => "bmp",
        FILE_TYPE_RAW => "dng",
        FILE_TYPE_HEIC => "jpg", // конвертируем в jpg
        _ => "jpg",
    }
}

/// Распарсенный заголовок входящего пакета
#[derive(Debug)]
pub struct PacketHeader {
    pub file_type:  u8,
    pub file_size:  u64,
    pub sha256:     [u8; 32],
    pub timestamp:  i64,
    pub name_len:   u32,
}

/// Распарсенный auth-пакет
#[derive(Debug)]
pub struct AuthPacket {
    pub username: String,
    pub hmac:     [u8; 32],
}

/// Читает ровно `n` байт из потока, блокируясь до получения всех
pub fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<()> {
    let mut total = 0;
    while total < buf.len() {
        let n = stream.read(&mut buf[total..])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before all data received",
            ));
        }
        total += n;
    }
    Ok(())
}

/// Читает и разбирает auth-пакет
/// Формат: [1B: 0x10][4B: username_len][username bytes][32B: HMAC]
pub fn read_auth_packet(stream: &mut TcpStream) -> io::Result<AuthPacket> {
    // Читаем тип пакета (должен быть PACKET_AUTH)
    let mut type_buf = [0u8; 1];
    read_exact(stream, &mut type_buf)?;
    if type_buf[0] != PACKET_AUTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected auth packet 0x10, got 0x{:02X}", type_buf[0]),
        ));
    }

    // Читаем длину username
    let mut len_buf = [0u8; 4];
    read_exact(stream, &mut len_buf)?;
    let username_len = u32::from_be_bytes(len_buf);

    if username_len == 0 || username_len > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid username length: {}", username_len),
        ));
    }

    // Читаем username
    let mut username_buf = vec![0u8; username_len as usize];
    read_exact(stream, &mut username_buf)?;
    let username = String::from_utf8(username_buf).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("username not valid UTF-8: {}", e))
    })?;

    // Валидируем username: только [a-zA-Z0-9_-]
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "username contains invalid characters",
        ));
    }

    // Читаем HMAC
    let mut hmac_buf = [0u8; 32];
    read_exact(stream, &mut hmac_buf)?;

    Ok(AuthPacket { username, hmac: hmac_buf })
}

/// Читает и разбирает заголовок файла из TCP-потока
pub fn read_header(stream: &mut TcpStream) -> io::Result<PacketHeader> {
    let mut buf = [0u8; HEADER_SIZE];
    read_exact(stream, &mut buf)?;

    let file_type = buf[0];

    if !is_valid_file_type(file_type) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown file type byte: 0x{:02X}", file_type),
        ));
    }

    let file_size = u64::from_be_bytes(buf[1..9].try_into().unwrap());

    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&buf[9..41]);

    let timestamp = i64::from_be_bytes(buf[41..49].try_into().unwrap());
    let name_len  = u32::from_be_bytes(buf[49..53].try_into().unwrap());

    if name_len == 0 || name_len > 512 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid filename length: {}", name_len),
        ));
    }

    if file_size == 0 || file_size > 10 * 1024 * 1024 * 1024 {
        // > 10 GB — явно что-то не так
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("suspicious file size: {} bytes", file_size),
        ));
    }

    Ok(PacketHeader { file_type, file_size, sha256, timestamp, name_len })
}

/// Читает имя файла (name_len байт) из потока
pub fn read_filename(stream: &mut TcpStream, name_len: u32) -> io::Result<String> {
    let mut name_buf = vec![0u8; name_len as usize];
    read_exact(stream, &mut name_buf)?;
    String::from_utf8(name_buf).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("filename not valid UTF-8: {}", e))
    })
}
