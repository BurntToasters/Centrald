use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const DEFAULT_REPO_URL: &str = "https://github.com/BurntToasters/centrald";
const DEFAULT_RELEASE_CHANNEL: &str = "prerelease";
const DEFAULT_RELEASE_MANIFEST: &str = "centrald-release.yml";
const DEFAULT_TAURI_MANIFEST: &str = "centrald-admin-updater.json";
const ALLOWED_KEYS: [&str; 8] = [
    "REPO_URL",
    "UPDATE_BASE_URL",
    "ARTIFACT_BASE_URL_TEMPLATE",
    "RELEASE_CHANNEL",
    "RELEASE_MANIFEST",
    "TAURI_UPDATE_MANIFEST",
    "TAURI_UPDATER_PUBKEY",
    "MINISIGN_PUBLIC_KEY",
];

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned()),
    );
    let root = manifest_dir.join("../..");
    let config_path = root.join("centrald.config");
    println!("cargo:rerun-if-changed={}", config_path.display());

    let values = read_config(&config_path);
    let repo_url = value(&values, "REPO_URL", DEFAULT_REPO_URL);
    validate_https_base(&repo_url, "REPO_URL");
    let release_channel = value(&values, "RELEASE_CHANNEL", DEFAULT_RELEASE_CHANNEL);
    if !is_channel(&release_channel) {
        panic!("RELEASE_CHANNEL must be a lowercase channel name");
    }
    let update_base = values
        .get("UPDATE_BASE_URL")
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| default_update_base(&repo_url, &release_channel));
    validate_https_base(&update_base, "UPDATE_BASE_URL");
    let artifact_template = values
        .get("ARTIFACT_BASE_URL_TEMPLATE")
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| default_artifact_template(&repo_url));
    validate_artifact_template(&artifact_template);
    let release_manifest = value(&values, "RELEASE_MANIFEST", DEFAULT_RELEASE_MANIFEST);
    let tauri_manifest = value(
        &values,
        "TAURI_UPDATE_MANIFEST",
        DEFAULT_TAURI_MANIFEST,
    );
    validate_filename(&release_manifest, "RELEASE_MANIFEST");
    validate_filename(&tauri_manifest, "TAURI_UPDATE_MANIFEST");
    let updater_pubkey = values
        .get("TAURI_UPDATER_PUBKEY")
        .map_or("", String::as_str)
        .trim();
    validate_public_value(updater_pubkey, "TAURI_UPDATER_PUBKEY");
    let minisign_public_key = values
        .get("MINISIGN_PUBLIC_KEY")
        .map_or("", String::as_str)
        .trim();
    validate_minisign_public_key(minisign_public_key);

    emit("CENTRALD_REPO_URL", repo_url.trim_end_matches('/'));
    emit("CENTRALD_UPDATE_BASE_URL", update_base.trim_end_matches('/'));
    emit(
        "CENTRALD_ARTIFACT_BASE_URL_TEMPLATE",
        artifact_template.trim_end_matches('/'),
    );
    emit("CENTRALD_RELEASE_CHANNEL", &release_channel);
    emit("CENTRALD_RELEASE_MANIFEST", &release_manifest);
    emit("CENTRALD_TAURI_UPDATE_MANIFEST", &tauri_manifest);
    emit("CENTRALD_TAURI_UPDATER_PUBKEY", updater_pubkey);
    emit("CENTRALD_MINISIGN_PUBLIC_KEY", minisign_public_key);
}

fn read_config(path: &Path) -> BTreeMap<String, String> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        println!(
            "cargo:warning={} was not found; using CentralD defaults",
            path.display()
        );
        return BTreeMap::new();
    };

    let allowed: BTreeSet<&str> = ALLOWED_KEYS.into_iter().collect();
    let mut values = BTreeMap::new();
    for (index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            panic!(
                "{}:{}: expected KEY=value",
                path.display(),
                index + 1
            );
        };
        let key = key.trim();
        if !allowed.contains(key) {
            panic!("{}:{}: unknown key {key}", path.display(), index + 1);
        }
        if values.contains_key(key) {
            panic!("{}:{}: duplicate key {key}", path.display(), index + 1);
        }
        values.insert(key.to_owned(), unquote(value.trim()).to_owned());
    }
    values
}

fn value(values: &BTreeMap<String, String>, key: &str, default: &str) -> String {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| default.to_owned())
}

fn default_update_base(repo_url: &str, release_channel: &str) -> String {
    let repo_url = repo_url.trim_end_matches('/');
    if is_github(repo_url) {
        if release_channel == "stable" {
            format!("{repo_url}/releases/latest/download")
        } else {
            let repository = repo_url
                .strip_prefix("https://github.com/")
                .unwrap_or_else(|| {
                    panic!("GitHub REPO_URL must use https://github.com/owner/repository")
                });
            let mut pieces = repository.split('/');
            let owner = pieces.next().unwrap_or_default();
            let repository = pieces.next().unwrap_or_default();
            if owner.is_empty() || repository.is_empty() || pieces.next().is_some() {
                panic!("GitHub REPO_URL must contain exactly owner/repository");
            }
            format!(
                "https://raw.githubusercontent.com/{owner}/{repository}/centrald-channels/channels/{release_channel}/latest"
            )
        }
    } else if release_channel == "stable" {
        format!("{repo_url}/latest")
    } else {
        format!("{repo_url}/{release_channel}/latest")
    }
}

fn default_artifact_template(repo_url: &str) -> String {
    let repo_url = repo_url.trim_end_matches('/');
    if is_github(repo_url) {
        format!("{repo_url}/releases/download/{{tag}}")
    } else {
        format!("{repo_url}/releases/{{version}}")
    }
}

fn is_github(value: &str) -> bool {
    value
        .strip_prefix("https://")
        .is_some_and(|rest| rest.to_ascii_lowercase().starts_with("github.com/"))
}

fn validate_https_base(value: &str, key: &str) {
    let value = value.trim();
    let rest = value
        .strip_prefix("https://")
        .unwrap_or_else(|| panic!("{key} must be an absolute HTTPS URL"));
    if rest.is_empty()
        || rest.starts_with('/')
        || value.contains(char::is_whitespace)
        || value.contains('@')
        || value.contains('?')
        || value.contains('#')
    {
        panic!("{key} must be HTTPS without credentials, whitespace, a query, or a fragment");
    }
}

fn validate_artifact_template(value: &str) {
    if !value.contains("{version}") && !value.contains("{tag}") {
        panic!("ARTIFACT_BASE_URL_TEMPLATE must contain {{version}} or {{tag}}");
    }
    let concrete = value
        .replace("{version}", "1.2.3")
        .replace("{tag}", "v1.2.3");
    validate_https_base(&concrete, "ARTIFACT_BASE_URL_TEMPLATE");
}

fn is_channel(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    value.len() <= 32
        && first.is_ascii_lowercase()
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '_' | '-')
        })
}

fn validate_filename(value: &str, key: &str) {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('.')
        || value.contains('/')
        || value.contains('\\')
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
    {
        panic!("{key} must be a simple file name");
    }
}

fn validate_public_value(value: &str, key: &str) {
    if value.contains('\n') || value.contains('\r') || value.contains('\0') {
        panic!("{key} must be a single-line public value");
    }
}

fn validate_minisign_public_key(value: &str) {
    validate_public_value(value, "MINISIGN_PUBLIC_KEY");
    if value.is_empty() {
        return;
    }
    if !value.starts_with("RW")
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '='))
    {
        panic!("MINISIGN_PUBLIC_KEY must be the base64 public key beginning with RW");
    }
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(value)
}

fn emit(key: &str, value: &str) {
    assert!(
        !value.contains('\n') && !value.contains('\r') && !value.contains('\0'),
        "{key} contains a forbidden control character"
    );
    println!("cargo:rustc-env={key}={value}");
}
