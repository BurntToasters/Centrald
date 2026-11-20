//! Passwords, sessions, two-factor codes, and brute-force throttling.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use anyhow::{Result, anyhow};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::db::now;

pub const SESSION_COOKIE: &str = "__Host-centrald";
/// A session ends after this long without a request…
pub const SESSION_IDLE_SECONDS: i64 = 7 * 24 * 60 * 60;
/// …and never outlives this, however active it is.
pub const SESSION_MAX_SECONDS: i64 = 30 * 24 * 60 * 60;

pub const MIN_PASSWORD_CHARS: usize = 10;
pub const MAX_PASSWORD_BYTES: usize = 256;
pub const MAX_USERNAME_BYTES: usize = 64;

const TOTP_STEP_SECONDS: i64 = 30;
const TOTP_DIGITS: u32 = 6;

fn hasher() -> Result<Argon2<'static>> {
    // OWASP-recommended Argon2id parameters: 19 MiB, 2 passes.
    let params = Params::new(19 * 1024, 2, 1, None).map_err(|error| anyhow!("{error}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hashes a password. CPU and memory heavy: call from the blocking pool.
pub fn hash_password(password: &str) -> Result<String> {
    let mut salt_bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|error| anyhow!("salt: {error}"))?;
    Ok(hasher()?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| anyhow!("hash password: {error}"))?
        .to_string())
}

/// Verifies a password. CPU and memory heavy: call from the blocking pool.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    let Ok(hasher) = hasher() else {
        return false;
    };
    hasher.verify_password(password.as_bytes(), &parsed).is_ok()
}

/// Hash of a discarded random password, so a login for an unknown user costs
/// the same Argon2 work as one for a real user.
pub fn dummy_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        let (random, _) = new_session_token();
        hash_password(&random).unwrap_or_default()
    })
}

pub fn validate_username(username: &str) -> Result<(), &'static str> {
    if username.is_empty() || username.len() > MAX_USERNAME_BYTES {
        return Err("Choose a username between 1 and 64 characters.");
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
    {
        return Err("Usernames may contain letters, digits, and . _ - @ only.");
    }
    Ok(())
}

pub fn validate_password(password: &str, username: &str) -> Result<(), &'static str> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err("Use a password of at least 10 characters.");
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err("That password is too long.");
    }
    if password.eq_ignore_ascii_case(username) {
        return Err("The password cannot be the same as the username.");
    }
    Ok(())
}

/// Returns `(cookie value, hash stored in the database)`.
pub fn new_session_token() -> (String, [u8; 32]) {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = centrald_proto::sha256(token.as_bytes());
    (token, hash)
}

pub fn session_hash(cookie_value: &str) -> [u8; 32] {
    centrald_proto::sha256(cookie_value.as_bytes())
}

/// One-time code an operator reads from the server to claim a new install.
pub fn new_setup_code() -> String {
    // No 0/O/1/I/L so it survives being read aloud or typed by hand.
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut code = String::with_capacity(14);
    for index in 0..12 {
        if index > 0 && index % 4 == 0 {
            code.push('-');
        }
        let pick = rand::random_range(0..ALPHABET.len());
        code.push(char::from(ALPHABET[pick]));
    }
    code
}

/// Compares setup codes ignoring case, spaces, and dashes, in constant time.
pub fn setup_code_matches(expected: &str, provided: &str) -> bool {
    fn normalize(value: &str) -> Vec<u8> {
        value
            .bytes()
            .filter(u8::is_ascii_alphanumeric)
            .map(|b| b.to_ascii_uppercase())
            .collect()
    }
    let expected = normalize(expected);
    let provided = normalize(provided);
    expected.len() == provided.len() && bool::from(expected.ct_eq(&provided))
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Fresh base32 TOTP secret (160 bits).
pub fn new_totp_secret() -> String {
    let mut bytes = [0_u8; 20];
    rand::rng().fill_bytes(&mut bytes);
    data_encoding::BASE32_NOPAD.encode(&bytes)
}

pub fn totp_uri(username: &str, secret: &str) -> String {
    format!("otpauth://totp/CentralD:{username}?secret={secret}&issuer=CentralD&digits=6&period=30")
}

fn totp_at(secret: &[u8], step: i64) -> Option<u32> {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).ok()?;
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let slice: [u8; 4] = digest.get(offset..offset + 4)?.try_into().ok()?;
    Some((u32::from_be_bytes(slice) & 0x7fff_ffff) % 10_u32.pow(TOTP_DIGITS))
}

/// Checks a six-digit code, tolerating one step of clock drift either way.
///
/// Returns the matched time step so the caller can reject a replay of the
/// same code (`last_step` is the step that was last accepted).
pub fn verify_totp(secret_base32: &str, code: &str, last_step: i64) -> Option<i64> {
    let code = code.trim().replace(' ', "");
    if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let expected: u32 = code.parse().ok()?;
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .ok()?;
    let current = now() / TOTP_STEP_SECONDS;
    (current - 1..=current + 1).find(|&step| {
        step > last_step
            && totp_at(&secret, step)
                .is_some_and(|value| bool::from(value.to_be_bytes().ct_eq(&expected.to_be_bytes())))
    })
}

/// Counts recent failures per key and locks a key out with growing delays.
#[derive(Debug, Default)]
pub struct RateLimiter {
    entries: Mutex<HashMap<String, Attempts>>,
}

#[derive(Debug, Clone, Copy)]
struct Attempts {
    failures: u32,
    last_failure: i64,
    locked_until: i64,
}

impl RateLimiter {
    const FREE_FAILURES: u32 = 5;
    const BASE_LOCK_SECONDS: i64 = 30;
    const MAX_LOCK_SECONDS: i64 = 15 * 60;
    const FORGET_AFTER_SECONDS: i64 = 60 * 60;

    /// `Err(seconds)` while the key is locked out.
    pub fn check(&self, key: &str) -> Result<(), i64> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        match entries.get(key) {
            Some(attempts) if attempts.locked_until > now() => Err(attempts.locked_until - now()),
            _ => Ok(()),
        }
    }

    pub fn record_failure(&self, key: &str) {
        let time = now();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() > 10_000 {
            entries.retain(|_, a| time - a.last_failure < Self::FORGET_AFTER_SECONDS);
        }
        let attempts = entries.entry(key.to_owned()).or_insert(Attempts {
            failures: 0,
            last_failure: time,
            locked_until: 0,
        });
        if time - attempts.last_failure > Self::FORGET_AFTER_SECONDS {
            attempts.failures = 0;
        }
        attempts.failures += 1;
        attempts.last_failure = time;
        if attempts.failures >= Self::FREE_FAILURES {
            let doublings = (attempts.failures - Self::FREE_FAILURES).min(10);
            let lock = (Self::BASE_LOCK_SECONDS << doublings).min(Self::MAX_LOCK_SECONDS);
            attempts.locked_until = time + lock;
        }
    }

    pub fn record_success(&self, key: &str) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
    }
}
