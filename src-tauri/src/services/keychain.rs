/// macOS Keychain integration via the `security` CLI.
///
/// Prevents API keys from being stored as plaintext in the cc-switch SQLite database.
/// Instead, keys are stored in the macOS system Keychain and the DB only contains
/// the placeholder string `FROM_KEYCHAIN`.
///
/// On non-macOS platforms, these functions are no-ops — the key remains in the DB.
use std::process::Command;

#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "com.mayer.apikeys";

/// The sentinel value written to the database in place of the real API key.
const FROM_KEYCHAIN: &str = "FROM_KEYCHAIN";

/// Sensitive JSON fields that should never be stored as plaintext in the DB.
const SENSITIVE_KEYS: &[&str] = &[
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
];

// ── Write path ────────────────────────────────────────────────────

/// Scan `settings_config` JSON for sensitive fields containing real API keys,
/// store each one in the macOS Keychain, and replace the value with `FROM_KEYCHAIN`.
///
/// The Keychain account name is derived from the field name (lowercased).
/// Returns the modified JSON value (mutated in place).
#[cfg(target_os = "macos")]
pub fn redirect_keys_to_keychain(settings_config: &mut serde_json::Value) {
    let obj = match settings_config.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    // Walk into the "env" and "auth" sub-objects where keys typically live.
    for sub_key in &["env", "auth"] {
        if let Some(sub) = obj.get_mut(*sub_key).and_then(|v| v.as_object_mut()) {
            for sensitive in SENSITIVE_KEYS {
                if let Some(val) = sub.get(*sensitive).and_then(|v| v.as_str()) {
                    if val.is_empty() || val == FROM_KEYCHAIN {
                        continue;
                    }
                    // This is a real key — store it in Keychain.
                    let account = format!("ccswitch.{}", sensitive.to_lowercase());
                    if store_in_keychain(&account, val) {
                        sub[*sensitive] = serde_json::Value::String(FROM_KEYCHAIN.to_string());
                        log::info!("KEYCHAIN: Stored {sensitive} → account {account}");
                    }
                }
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn redirect_keys_to_keychain(_settings_config: &mut serde_json::Value) {
    // No-op on non-macOS — key stays in the DB.
}

#[cfg(target_os = "macos")]
fn store_in_keychain(account: &str, value: &str) -> bool {
    Command::new("security")
        .args([
            "add-generic-password",
            "-s", KEYCHAIN_SERVICE,
            "-a", account,
            "-w", value,
            "-U", // update if exists
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ── Read path ─────────────────────────────────────────────────────

/// If the given value is `FROM_KEYCHAIN`, read the real key from macOS Keychain.
/// Otherwise return the value unchanged.
#[cfg(target_os = "macos")]
pub fn expand_keychain_value(value: &str) -> Option<String> {
    if value != FROM_KEYCHAIN {
        return Some(value.to_string());
    }
    // We need to know which account to read. Callers must pass the account name.
    None // Callers should use `expand_with_account` instead.
}

/// Read a specific key from Keychain by account name.
#[cfg(target_os = "macos")]
pub fn load_from_keychain(account: &str) -> Option<String> {
    let output = Command::new("security")
        .args([
            "find-generic-password",
            "-s", KEYCHAIN_SERVICE,
            "-a", account,
            "-w",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn load_from_keychain(_account: &str) -> Option<String> {
    None
}

/// Expand a `FROM_KEYCHAIN` placeholder in a `settings_config` JSON into the real key
/// by matching the known sensitive field name → Keychain account.
#[cfg(target_os = "macos")]
pub fn expand_settings_config(mut config: serde_json::Value) -> serde_json::Value {
    let obj = match config.as_object_mut() {
        Some(o) => o,
        None => return config,
    };
    for sub_key in &["env", "auth"] {
        if let Some(sub) = obj.get_mut(*sub_key).and_then(|v| v.as_object_mut()) {
            for sensitive in SENSITIVE_KEYS {
                if let Some(val) = sub.get(*sensitive).and_then(|v| v.as_str()) {
                    if val == FROM_KEYCHAIN {
                        let account = format!("ccswitch.{}", sensitive.to_lowercase());
                        if let Some(real_key) = load_from_keychain(&account) {
                            sub[*sensitive] = serde_json::Value::String(real_key);
                        }
                    }
                }
            }
        }
    }
    config
}

#[cfg(not(target_os = "macos"))]
pub fn expand_settings_config(config: serde_json::Value) -> serde_json::Value {
    config
}

/// If `value` is `FROM_KEYCHAIN`, read the real key from macOS Keychain using
/// the given `sensitive_key` name (e.g. "ANTHROPIC_AUTH_TOKEN") as the account.
/// Otherwise return the value unchanged.
#[cfg(target_os = "macos")]
pub fn resolve_key(value: &str, sensitive_key: &str) -> Option<String> {
    if value == FROM_KEYCHAIN {
        let account = format!("ccswitch.{}", sensitive_key.to_lowercase());
        let real = load_from_keychain(&account)?;
        log::info!("KEYCHAIN: Resolved {sensitive_key} from keychain");
        return Some(real);
    }
    Some(value.to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn resolve_key(value: &str, _sensitive_key: &str) -> Option<String> {
    Some(value.to_string())
}
