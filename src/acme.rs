use std::{
    cmp::Ordering,
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, bail, ensure};
use boring::{
    asn1::Asn1Time,
    pkey::PKey,
    ssl::{SslContextBuilder, SslMethod},
    x509::X509,
};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
    time,
};
use tracing::{debug, info, warn};

use crate::config::{AcmeConfig, Config};

const CERT_FILE: &str = "cert.pem";
const KEY_FILE: &str = "key.pem";
const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Clone)]
pub struct AcmeManager {
    cfg: AcmeConfig,
    account: Account,
    challenges: ChallengeStore,
    targets: Vec<AcmeTarget>,
}

impl AcmeManager {
    pub async fn prepare(config: &mut Config) -> anyhow::Result<Option<Self>> {
        let cfg = config.acme_config();
        let targets = configure_targets(config, &cfg)?;
        if targets.is_empty() {
            return Ok(None);
        }

        let challenges = ChallengeStore::default();
        start_challenge_server(cfg.http_listen, challenges.clone()).await?;
        let account = load_account(&cfg).await?;
        let manager = Self {
            cfg,
            account,
            challenges,
            targets,
        };
        manager.prepare_certificates().await?;
        Ok(Some(manager))
    }

    pub fn spawn_renewal_tasks(&self) {
        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                time::sleep(RENEWAL_CHECK_INTERVAL).await;
                for target in &manager.targets {
                    if let Err(err) = manager.renew_if_due(target).await {
                        warn!(
                            domains = ?target.domains,
                            %err,
                            "ACME certificate renewal failed"
                        );
                    }
                }
            }
        });
    }

    async fn prepare_certificates(&self) -> anyhow::Result<()> {
        for target in &self.targets {
            fs::create_dir_all(&target.dir).with_context(|| {
                format!(
                    "failed to create ACME cache directory {}",
                    target.dir.display()
                )
            })?;

            match certificate_cache_status(target, self.cfg.renew_before_days) {
                CacheStatus::Valid => {
                    info!(
                        domains = ?target.domains,
                        certificate = %target.cert_path.display(),
                        "using cached ACME certificate"
                    );
                }
                CacheStatus::RenewDue => {
                    info!(domains = ?target.domains, "cached ACME certificate is due for renewal");
                    if let Err(err) = self.issue_certificate(target).await {
                        warn!(
                            domains = ?target.domains,
                            %err,
                            "ACME renewal failed; continuing with cached certificate"
                        );
                    }
                }
                CacheStatus::MissingOrInvalid => {
                    self.issue_certificate(target).await.with_context(|| {
                        format!(
                            "failed to obtain ACME certificate for {} and no valid cached certificate is available",
                            target.domains.join(", ")
                        )
                    })?;
                }
            }
        }
        Ok(())
    }

    async fn renew_if_due(&self, target: &AcmeTarget) -> anyhow::Result<()> {
        match certificate_cache_status(target, self.cfg.renew_before_days) {
            CacheStatus::Valid => Ok(()),
            CacheStatus::RenewDue | CacheStatus::MissingOrInvalid => {
                self.issue_certificate(target).await
            }
        }
    }

    async fn issue_certificate(&self, target: &AcmeTarget) -> anyhow::Result<()> {
        let mut tokens = Vec::new();
        let result = self.issue_certificate_inner(target, &mut tokens).await;
        for token in tokens {
            self.challenges.remove(&token).await;
        }
        result
    }

    async fn issue_certificate_inner(
        &self,
        target: &AcmeTarget,
        tokens: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        info!(domains = ?target.domains, "requesting ACME certificate");
        let identifiers = target
            .domains
            .iter()
            .cloned()
            .map(Identifier::Dns)
            .collect::<Vec<_>>();
        let mut order = self
            .account
            .new_order(&NewOrder::new(identifiers.as_slice()))
            .await?;

        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => bail!("unexpected ACME authorization status {other:?}"),
            }

            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .context("ACME authorization did not offer an HTTP-01 challenge")?;
            let token = challenge.token.clone();
            let key_authorization = challenge.key_authorization().as_str().to_owned();
            self.challenges
                .insert(token.clone(), key_authorization)
                .await;
            tokens.push(token);
            challenge.set_ready().await?;
        }
        drop(authorizations);

        let retry = RetryPolicy::new().timeout(Duration::from_secs(90));
        let status = order.poll_ready(&retry).await?;
        ensure!(
            status == OrderStatus::Ready,
            "ACME order was not ready after validation: {status:?}"
        );

        let private_key_pem = order.finalize().await?;
        let cert_chain_pem = order.poll_certificate(&retry).await?;
        validate_certificate_pair(&cert_chain_pem, &private_key_pem)
            .context("ACME CA returned an unusable certificate or key")?;
        atomic_write(&target.key_path, private_key_pem.as_bytes())?;
        atomic_write(&target.cert_path, cert_chain_pem.as_bytes())?;
        info!(
            domains = ?target.domains,
            certificate = %target.cert_path.display(),
            "stored ACME certificate"
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct AcmeTarget {
    domains: Vec<String>,
    dir: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
}

#[derive(Clone, Default)]
struct ChallengeStore {
    inner: Arc<RwLock<HashMap<String, String>>>,
}

impl ChallengeStore {
    async fn insert(&self, token: String, key_authorization: String) {
        self.inner.write().await.insert(token, key_authorization);
    }

    async fn remove(&self, token: &str) {
        self.inner.write().await.remove(token);
    }

    async fn get(&self, token: &str) -> Option<String> {
        self.inner.read().await.get(token).cloned()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CacheStatus {
    Valid,
    RenewDue,
    MissingOrInvalid,
}

fn configure_targets(
    config: &mut Config,
    acme_cfg: &AcmeConfig,
) -> anyhow::Result<Vec<AcmeTarget>> {
    let mut targets_by_domains = HashMap::<Vec<String>, AcmeTarget>::new();

    for inbound in &mut config.inbounds {
        let Some(tls) = inbound.tls.as_mut() else {
            continue;
        };
        let Some(acme) = tls.acme.as_mut() else {
            continue;
        };

        acme.domains.sort();
        acme.domains.dedup();

        let domains = acme.domains.clone();
        let target = targets_by_domains
            .entry(domains.clone())
            .or_insert_with(|| target_for_domains(acme_cfg, &domains));

        tls.certificate = Some(target.cert_path.to_string_lossy().into_owned());
        tls.private_key = Some(target.key_path.to_string_lossy().into_owned());
    }

    Ok(targets_by_domains.into_values().collect())
}

fn target_for_domains(acme_cfg: &AcmeConfig, domains: &[String]) -> AcmeTarget {
    let slug = domain_slug(domains);
    let dir = acme_cfg.cache_dir.join("certificates").join(slug);
    AcmeTarget {
        domains: domains.to_vec(),
        cert_path: dir.join(CERT_FILE),
        key_path: dir.join(KEY_FILE),
        dir,
    }
}

async fn start_challenge_server(
    listen: std::net::SocketAddr,
    challenges: ChallengeStore,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind ACME HTTP-01 listener on {listen}"))?;
    info!(%listen, "ACME HTTP-01 challenge listener started");
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let challenges = challenges.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_challenge_connection(stream, challenges).await {
                            debug!(%peer, %err, "ACME HTTP-01 request failed");
                        }
                    });
                }
                Err(err) => warn!(%err, "ACME HTTP-01 listener accept failed"),
            }
        }
    });
    Ok(())
}

async fn handle_challenge_connection(
    mut stream: TcpStream,
    challenges: ChallengeStore,
) -> anyhow::Result<()> {
    let mut buf = [0_u8; 2048];
    let n = stream.read(&mut buf).await?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let request_line = request.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    let body = match (method, challenge_token(path)) {
        ("GET", Some(token)) => challenges.get(token).await,
        _ => None,
    };

    if let Some(body) = body {
        write_http_response(&mut stream, 200, "OK", body.as_bytes()).await?;
    } else {
        write_http_response(&mut stream, 404, "Not Found", b"not found\n").await?;
    }
    Ok(())
}

fn challenge_token(path: &str) -> Option<&str> {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    let token = path.strip_prefix("/.well-known/acme-challenge/")?;
    (!token.is_empty() && !token.contains('/')).then_some(token)
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
) -> anyhow::Result<()> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn load_account(cfg: &AcmeConfig) -> anyhow::Result<Account> {
    let accounts_dir = cfg.cache_dir.join("accounts");
    fs::create_dir_all(&accounts_dir).with_context(|| {
        format!(
            "failed to create ACME account cache directory {}",
            accounts_dir.display()
        )
    })?;
    let account_path = accounts_dir.join(format!("{}.json", directory_slug(&cfg.directory)));

    if account_path.exists() {
        let raw = fs::read_to_string(&account_path)
            .with_context(|| format!("failed to read ACME account {}", account_path.display()))?;
        let credentials: AccountCredentials = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse ACME account {}", account_path.display()))?;
        return Account::builder()?
            .from_credentials(credentials)
            .await
            .context("failed to restore ACME account");
    }

    ensure!(
        cfg.accept_terms,
        "ACME account creation requires acme.accept_terms = true"
    );

    let directory_url = directory_url(&cfg.directory)?;
    let contacts = cfg.contact.iter().map(String::as_str).collect::<Vec<_>>();
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: contacts.as_slice(),
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
        .await
        .context("failed to create ACME account")?;
    let raw = serde_json::to_vec_pretty(&credentials)?;
    atomic_write(&account_path, &raw)?;
    Ok(account)
}

fn directory_url(raw: &str) -> anyhow::Result<String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "letsencrypt-staging" | "letsencrypt_staging" | "staging" => {
            Ok(LetsEncrypt::Staging.url().to_owned())
        }
        "letsencrypt-production" | "letsencrypt_production" | "production" => {
            Ok(LetsEncrypt::Production.url().to_owned())
        }
        _ if raw.starts_with("https://") || raw.starts_with("http://") => Ok(raw.to_owned()),
        _ => bail!(
            "unsupported ACME directory {raw:?}; use letsencrypt-staging, letsencrypt-production, or a full URL"
        ),
    }
}

fn certificate_cache_status(target: &AcmeTarget, renew_before_days: u32) -> CacheStatus {
    let Ok(cert_pem) = fs::read(&target.cert_path) else {
        return CacheStatus::MissingOrInvalid;
    };
    let Ok(key_pem) = fs::read(&target.key_path) else {
        return CacheStatus::MissingOrInvalid;
    };
    if validate_certificate_pair_bytes(&cert_pem, &key_pem).is_err() {
        return CacheStatus::MissingOrInvalid;
    }

    let Ok(certs) = X509::stack_from_pem(&cert_pem) else {
        return CacheStatus::MissingOrInvalid;
    };
    let Some(leaf) = certs.first() else {
        return CacheStatus::MissingOrInvalid;
    };
    let Ok(now) = Asn1Time::days_from_now(0) else {
        return CacheStatus::MissingOrInvalid;
    };
    let Ok(renew_after) = Asn1Time::days_from_now(renew_before_days) else {
        return CacheStatus::MissingOrInvalid;
    };
    if leaf
        .not_after()
        .compare(&now)
        .is_ok_and(|ordering| ordering != Ordering::Greater)
    {
        return CacheStatus::MissingOrInvalid;
    }
    if leaf
        .not_after()
        .compare(&renew_after)
        .is_ok_and(|ordering| ordering != Ordering::Greater)
    {
        return CacheStatus::RenewDue;
    }
    CacheStatus::Valid
}

fn validate_certificate_pair(cert_pem: &str, key_pem: &str) -> anyhow::Result<()> {
    validate_certificate_pair_bytes(cert_pem.as_bytes(), key_pem.as_bytes())
}

fn validate_certificate_pair_bytes(cert_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<()> {
    let certs = X509::stack_from_pem(cert_pem)?;
    ensure!(!certs.is_empty(), "certificate chain is empty");
    let key = PKey::private_key_from_pem(key_pem)?;
    let mut builder = SslContextBuilder::new(SslMethod::tls_server())?;
    builder.set_certificate(&certs[0])?;
    builder.set_private_key(&key)?;
    builder.check_private_key()?;
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    let tmp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("pem")
    ));
    fs::write(&tmp_path, bytes)
        .with_context(|| format!("failed to write temporary file {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to replace {} with {}",
            path.display(),
            tmp_path.display()
        )
    })?;
    Ok(())
}

fn domain_slug(domains: &[String]) -> String {
    stable_slug(&domains.join("_"))
}

fn directory_slug(directory: &str) -> String {
    match directory.trim().to_ascii_lowercase().as_str() {
        "letsencrypt-staging" | "letsencrypt_staging" | "staging" => "letsencrypt-staging".into(),
        "letsencrypt-production" | "letsencrypt_production" | "production" => {
            "letsencrypt-production".into()
        }
        _ => stable_slug(directory),
    }
}

fn stable_slug(input: &str) -> String {
    let mut slug = input
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    while slug.contains("__") {
        slug = slug.replace("__", "_");
    }
    slug = slug.trim_matches('_').to_owned();
    if slug.is_empty() {
        slug = "default".to_owned();
    }
    if slug.len() <= 120 {
        return slug;
    }

    let digest = Sha256::digest(input.as_bytes());
    format!("{}-{}", &slug[..96], hex::encode(&digest[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_token_accepts_only_http01_path() {
        assert_eq!(
            challenge_token("/.well-known/acme-challenge/token123"),
            Some("token123")
        );
        assert_eq!(
            challenge_token("/.well-known/acme-challenge/token123?x=1"),
            Some("token123")
        );
        assert_eq!(challenge_token("/elsewhere/token123"), None);
        assert_eq!(challenge_token("/.well-known/acme-challenge/"), None);
        assert_eq!(challenge_token("/.well-known/acme-challenge/a/b"), None);
    }
}
