//! Bitwarden CLI credential provider
//!
//! Wraps the `bw` CLI tool to look up credentials, check vault status, and
//! unlock the vault.

use std::process::Command;

use ap_client::CredentialData;
use secrecy::{ExposeSecret, SecretString, zeroize::Zeroizing};
use serde::Deserialize;
use tracing::info;

use super::{CredentialProvider, CredentialQuery, LookupResult, ProviderStatus};

/// Fallback path when `bw` is not found on `$PATH` (macOS Homebrew default).
const BW_FALLBACK_PATH: &str = "/opt/homebrew/bin/bw";

/// Bitwarden CLI login item structure.
#[derive(Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<BwUri>>,
}

/// Bitwarden CLI URI structure.
#[derive(Deserialize)]
struct BwUri {
    uri: Option<String>,
}

/// Bitwarden CLI item structure.
#[derive(Deserialize)]
struct BwItem {
    id: Option<String>,
    login: Option<BwLogin>,
}

/// Credential provider backed by the Bitwarden CLI (`bw`).
pub struct BitwardenProvider {
    session: Option<SecretString>,
    /// Cached path to the `bw` binary (resolved once on construction).
    bw_path: Option<String>,
}

impl BitwardenProvider {
    /// Create a new provider, reading `BW_SESSION` from the environment if set.
    pub fn new() -> Self {
        let session = std::env::var("BW_SESSION")
            .ok()
            .filter(|s| !s.is_empty())
            .map(SecretString::from);
        let bw_path = resolve_bw_path();
        Self { session, bw_path }
    }
}

/// Find `bw` on `$PATH`, falling back to a well-known location.
/// Returns `None` only if neither is found.
fn resolve_bw_path() -> Option<String> {
    // Check $PATH first — use `where` on Windows, `which` on Unix
    let which_cmd = if cfg!(target_os = "windows") {
        "where"
    } else {
        "which"
    };
    let from_path = Command::new(which_cmd)
        .arg("bw")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            // `where` on Windows may return multiple lines; take the first one
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .unwrap_or_default()
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty());

    if from_path.is_some() {
        return from_path;
    }

    // Fall back to well-known location (macOS Homebrew default)
    if std::path::Path::new(BW_FALLBACK_PATH).exists() {
        Some(BW_FALLBACK_PATH.to_string())
    } else {
        None
    }
}

/// Run `bw unlock` with the given master password and return the session key.
fn run_bw_unlock(bw: &str, password: &str) -> Result<String, String> {
    let output = Command::new(bw)
        .args(["unlock", "--passwordenv", "BW_MASTER_PASSWORD", "--raw"])
        .env("BW_MASTER_PASSWORD", password)
        .output()
        .map_err(|e| format!("Failed to run bw unlock: {e}"))?;

    if output.status.success() {
        let key = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if key.is_empty() {
            Err("bw unlock returned empty session key".to_string())
        } else {
            Ok(key)
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if stderr.is_empty() {
            "bw unlock failed".to_string()
        } else {
            stderr
        })
    }
}

/// Run `bw status` and return the parsed status string and user email.
fn check_bw_cli_status(bw: &str, session: Option<&str>) -> (Option<String>, Option<String>) {
    let mut cmd = Command::new(bw);
    cmd.arg("status");
    if let Some(key) = session {
        cmd.env("BW_SESSION", key);
    }

    match cmd.output() {
        Ok(o) if o.status.success() => {
            let json: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_default();
            let status = json["status"].as_str().map(String::from);
            let user_email = json["userEmail"].as_str().map(String::from);
            (status, user_email)
        }
        _ => (None, None),
    }
}

/// Heuristic: a BW session key is exactly 88 characters of valid base64.
///
/// BW session keys are 64 bytes (two 32-byte keys), base64-encoded → 88 chars
/// with padding.
fn looks_like_session_key(input: &str) -> bool {
    input.len() == 88
        && input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

/// Look up credentials from the Bitwarden CLI.
///
/// `bw get item` refuses to pick when several items match, so in that case the
/// matches are listed with `bw list items --search` and narrowed to logins
/// whose URI host is exactly `search` (when any are). If more than one login
/// remains, all of them are returned so the user can choose.
fn lookup_credential(bw: &str, search: &str, session: Option<&str>) -> LookupResult {
    match bw_command(bw, &["get", "item", search], session) {
        Ok(stdout) => {
            return serde_json::from_slice::<BwItem>(&stdout)
                .ok()
                .and_then(item_to_credential)
                .map_or(LookupResult::NotFound, LookupResult::Found);
        }
        Err(stderr) if !stderr.contains("More than one result") => {
            if !stderr.contains("Not found") {
                info!("bw get item failed: {}", stderr);
            }
            return LookupResult::NotFound;
        }
        Err(_) => {}
    }

    let items: Vec<BwItem> = match bw_command(bw, &["list", "items", "--search", search], session)
        .map(|stdout| serde_json::from_slice(&stdout))
    {
        Ok(Ok(items)) => items,
        Ok(Err(e)) => {
            info!("bw list items returned invalid JSON: {}", e);
            return LookupResult::NotFound;
        }
        Err(stderr) => {
            info!("bw list items failed: {}", stderr);
            return LookupResult::NotFound;
        }
    };

    let mut candidates: Vec<CredentialData> = narrow_to_host(items, search)
        .into_iter()
        .filter_map(item_to_credential)
        .collect();
    match candidates.len() {
        0 => LookupResult::NotFound,
        1 => LookupResult::Found(candidates.remove(0)),
        _ => LookupResult::Multiple(candidates),
    }
}

/// Keep only the logins among `items`; if any of them has a URI whose host is
/// exactly `search`, keep only those.
fn narrow_to_host(items: Vec<BwItem>, search: &str) -> Vec<BwItem> {
    let logins: Vec<BwItem> = items.into_iter().filter(|i| i.login.is_some()).collect();
    let host_matches = |item: &BwItem| {
        item.login
            .as_ref()
            .and_then(|l| l.uris.as_ref())
            .is_some_and(|uris| {
                uris.iter().any(|u| {
                    u.uri
                        .as_deref()
                        .and_then(domain_from_uri)
                        .is_some_and(|h| h.eq_ignore_ascii_case(search))
                })
            })
    };
    if logins.iter().any(host_matches) {
        logins.into_iter().filter(host_matches).collect()
    } else {
        logins
    }
}

/// Run a `bw` subcommand, returning stdout on success or stderr on failure.
fn bw_command(bw: &str, args: &[&str], session: Option<&str>) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new(bw);
    cmd.args(args);
    if let Some(key) = session {
        cmd.env("BW_SESSION", key);
    }
    let output = cmd.output().map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

fn item_to_credential(item: BwItem) -> Option<CredentialData> {
    let login = item.login?;

    let uri = login
        .uris
        .as_ref()
        .and_then(|uris| uris.first())
        .and_then(|u| u.uri.clone());

    let domain = uri.as_deref().and_then(domain_from_uri);

    Some(CredentialData {
        username: login.username,
        password: login.password.map(Zeroizing::new),
        totp: login.totp,
        uri,
        notes: None,
        credential_id: item.id,
        domain,
    })
}

/// Extract the domain (host) from a URI string, e.g. `https://example.com/path` → `example.com`.
fn domain_from_uri(uri: &str) -> Option<String> {
    // Strip scheme (e.g. "https://")
    let after_scheme = match uri.split_once("://") {
        Some((_, rest)) => rest,
        None => uri,
    };
    // Strip userinfo (e.g. "user:pass@")
    let after_userinfo = match after_scheme.split_once('@') {
        Some((_, rest)) => rest,
        None => after_scheme,
    };
    // Take host (before any '/' or ':')
    let host = after_userinfo.split(['/', ':']).next()?;
    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
}

/// Create a `BitwardenProvider` with explicit fields (for testing without
/// spawning `which`).
#[cfg(test)]
impl BitwardenProvider {
    fn with_session(session: Option<SecretString>) -> Self {
        Self {
            session,
            bw_path: None,
        }
    }
}

impl CredentialProvider for BitwardenProvider {
    fn name(&self) -> &str {
        "Bitwarden"
    }

    fn status(&self) -> ProviderStatus {
        let bw = match &self.bw_path {
            Some(p) => p,
            None => {
                return ProviderStatus::NotInstalled {
                    install_hint: "Install the Bitwarden CLI and add it to your path: https://bitwarden.com/download/#command-line-interface".to_string(),
                };
            }
        };

        let (status_str, user_email) =
            check_bw_cli_status(bw, self.session.as_ref().map(|s| s.expose_secret()));

        match status_str.as_deref() {
            Some("unlocked") => ProviderStatus::Ready {
                user_info: user_email,
            },
            Some("locked") => ProviderStatus::Locked {
                prompt: "Master password or session key".to_string(),
                user_info: user_email,
            },
            Some(other) => ProviderStatus::Unavailable {
                reason: format!("Vault status: {other} — run: bw login"),
            },
            None => ProviderStatus::Unavailable {
                reason: "Could not determine vault status".to_string(),
            },
        }
    }

    fn unlock(&mut self, input: &str) -> Result<(), String> {
        let bw = self.bw_path.as_deref().ok_or("Bitwarden CLI not found")?;

        if looks_like_session_key(input) {
            // Try as a session key first — validate with `bw status`
            let (status, _) = check_bw_cli_status(bw, Some(input));
            if status.as_deref() == Some("unlocked") {
                self.session = Some(SecretString::from(input.to_string()));
                return Ok(());
            }
            // Fall through to try as password if it didn't validate
        }

        // Treat as master password
        let key = run_bw_unlock(bw, input)?;
        self.session = Some(SecretString::from(key));
        Ok(())
    }

    fn lookup(&self, query: &CredentialQuery) -> LookupResult {
        let bw = match &self.bw_path {
            Some(p) => p,
            None => {
                return LookupResult::NotReady {
                    message: "Bitwarden CLI not found".to_string(),
                };
            }
        };

        let search = query.search_string();

        match lookup_credential(bw, search, self.session.as_ref().map(|s| s.expose_secret())) {
            LookupResult::NotFound => {
                // When there's no cached session the vault might still be unlocked
                // natively (e.g. via BW_SESSION in the shell). Check `bw status`
                // to distinguish "not found" from "vault locked".
                if self.session.is_none() {
                    let (status, _) = check_bw_cli_status(bw, None);
                    if status.as_deref() != Some("unlocked") {
                        return LookupResult::NotReady {
                            message: "Vault is locked".to_string(),
                        };
                    }
                }
                LookupResult::NotFound
            }
            result => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- narrow_to_host() ----------------------------------------------------

    fn items(json: &str) -> Vec<BwItem> {
        serde_json::from_str(json).expect("valid test JSON")
    }

    fn ids(items: Vec<BwItem>) -> Vec<String> {
        items.into_iter().filter_map(|i| i.id).collect()
    }

    const GITHUB_ITEMS: &str = r#"[
        {"id":"a","login":{"username":"alice@example.com","password":"p1","uris":[{"uri":"https://github.com/login"}]}},
        {"id":"b","login":{"username":"bob","password":"p2","uris":[{"uri":"https://GitHub.com"}]}},
        {"id":"c","login":{"username":"carol","password":"p3","uris":[{"uri":"https://gist.github.com"}]}},
        {"id":"note"}
    ]"#;

    #[test]
    fn narrow_keeps_exact_host_logins() {
        assert_eq!(
            ids(narrow_to_host(items(GITHUB_ITEMS), "github.com")),
            ["a", "b"]
        );
    }

    #[test]
    fn narrow_prefers_exact_subdomain() {
        assert_eq!(
            ids(narrow_to_host(items(GITHUB_ITEMS), "gist.github.com")),
            ["c"]
        );
    }

    #[test]
    fn narrow_keeps_all_logins_when_no_exact_host() {
        assert_eq!(
            ids(narrow_to_host(items(GITHUB_ITEMS), "github")),
            ["a", "b", "c"]
        );
    }

    // -- looks_like_session_key() -------------------------------------------

    /// 88 A's — valid base64 of the right length.
    const VALID_KEY: &str =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn session_key_valid() {
        assert_eq!(VALID_KEY.len(), 88);
        assert!(looks_like_session_key(VALID_KEY));
    }

    #[test]
    fn session_key_rejects_wrong_length_and_bad_chars() {
        assert!(!looks_like_session_key(""));
        assert!(!looks_like_session_key("short"));
        assert!(!looks_like_session_key(&VALID_KEY[..87])); // too short
        assert!(!looks_like_session_key("alligator5")); // typical password
        // 88 chars but contains a space
        let mut bad = VALID_KEY.to_string();
        bad.replace_range(40..41, " ");
        assert!(!looks_like_session_key(&bad));
    }

    // -- domain_from_uri() ---------------------------------------------------

    #[test]
    fn domain_from_uri_with_scheme_and_path() {
        assert_eq!(
            domain_from_uri("https://example.com/path"),
            Some("example.com".into())
        );
    }

    #[test]
    fn domain_from_uri_with_port() {
        assert_eq!(
            domain_from_uri("https://example.com:8080/path"),
            Some("example.com".into())
        );
    }

    #[test]
    fn domain_from_uri_no_scheme() {
        assert_eq!(domain_from_uri("example.com"), Some("example.com".into()));
    }

    #[test]
    fn domain_from_uri_with_userinfo() {
        assert_eq!(
            domain_from_uri("https://user:pass@example.com"),
            Some("example.com".into())
        );
    }

    #[test]
    fn domain_from_uri_empty_host() {
        assert_eq!(domain_from_uri("https://"), None);
    }

    #[test]
    fn domain_from_uri_bare_scheme() {
        assert_eq!(domain_from_uri(""), None);
    }

    // -- BitwardenProvider construction & name() ----------------------------

    #[test]
    fn provider_name_is_bitwarden() {
        let p = BitwardenProvider::with_session(None);
        assert_eq!(p.name(), "Bitwarden");
    }

    #[test]
    fn provider_has_session_when_constructed_with_one() {
        let p = BitwardenProvider::with_session(Some(SecretString::from("key123".to_string())));
        assert!(p.session.is_some());
    }

    #[test]
    fn provider_has_no_session_when_constructed_without() {
        let p = BitwardenProvider::with_session(None);
        assert!(p.session.is_none());
    }
}
