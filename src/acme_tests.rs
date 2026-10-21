use super::*;
struct Temp(std::path::PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("rtunnel-test-acme-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// H: secret persistence enforces 0600 even when the launching shell has umask 022.
// The umask is changed only in a separate shell/child test process.
#[cfg(unix)]
#[test]
fn secret_files_use_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = std::env::var_os("RTUNNEL_PERMISSIONS_TEST_CHILD") {
        let path = std::path::PathBuf::from(dir).join("key.pem");
        atomic_write(&path, b"test-placeholder-not-a-real-key").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        eprintln!("actual production atomic_write mode={mode:04o}, expected=0600");
        assert_eq!(mode, 0o600);
        return;
    }
    let temp = Temp::new();
    let output = std::process::Command::new("/bin/sh")
        .args(["-c", "umask 022; exec \"$@\"", "test-umask"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "acme::regression_tests::secret_files_use_owner_only_permissions",
            "--nocapture",
        ])
        .env("RTUNNEL_PERMISSIONS_TEST_CHILD", &temp.0)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = output;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("permissions child exceeded its deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    eprintln!(
        "permissions child status={}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "secret file permissions failed in isolated umask child"
    );
}

// A failed commit must preserve the last valid certificate snapshot. No CA is contacted.
#[test]
fn failed_certificate_commit_preserves_valid_cache() {
    let temp = Temp::new();
    let target = AcmeTarget {
        domains: vec!["localhost".into()],
        dir: temp.0.clone(),
        cert_path: temp.0.join("cert.pem"),
        key_path: temp.0.join("key.pem"),
    };
    let key1 = rcgen::KeyPair::generate().unwrap();
    let cert1 = rcgen::CertificateParams::new(target.domains.clone())
        .unwrap()
        .self_signed(&key1)
        .unwrap();
    let key2 = rcgen::KeyPair::generate().unwrap();
    let cert2 = rcgen::CertificateParams::new(target.domains.clone())
        .unwrap()
        .self_signed(&key2)
        .unwrap();
    atomic_write(&target.key_path, key1.serialize_pem().as_bytes()).unwrap();
    atomic_write(&target.cert_path, cert1.pem().as_bytes()).unwrap();
    assert_eq!(certificate_cache_status(&target, 30), CacheStatus::Valid);
    validate_certificate_pair(&cert2.pem(), &key2.serialize_pem()).unwrap();
    publish_certificate(&target, &cert1.pem(), &key1.serialize_pem()).unwrap();
    let old_bundle = std::fs::read(target.bundle_path()).unwrap();
    let error = publish_certificate_with(
        &target,
        &cert2.pem(),
        &key2.serialize_pem(),
        |staged, destination| {
            // Inject failure at the actual production commit, not in a legacy helper.
            let staged = std::fs::read(staged).unwrap();
            validate_certificate_pair_bytes(&staged, &staged).unwrap();
            assert_eq!(std::fs::read(destination).unwrap(), old_bundle);
            Err(std::io::Error::other("injected publication failure"))
        },
    )
    .unwrap_err();
    let status = certificate_cache_status(&target, 30);
    eprintln!("publish failed={error:#}; cache_status={status:?}");
    assert_eq!(std::fs::read(target.bundle_path()).unwrap(), old_bundle);
    assert_ne!(
        status,
        CacheStatus::MissingOrInvalid,
        "second write failure invalidated the formerly usable cache"
    );
}

#[test]
fn legacy_cache_migrates_without_issuance() {
    let temp = Temp::new();
    let target = AcmeTarget {
        domains: vec!["localhost".into()],
        dir: temp.0.clone(),
        cert_path: temp.0.join("cert.pem"),
        key_path: temp.0.join("key.pem"),
    };
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(target.domains.clone())
        .unwrap()
        .self_signed(&key)
        .unwrap();
    std::fs::write(&target.cert_path, cert.pem()).unwrap();
    std::fs::write(&target.key_path, key.serialize_pem()).unwrap();
    migrate_cached_certificate(&target).unwrap();
    assert!(target.bundle_path().is_file());
    assert_eq!(certificate_cache_status(&target, 30), CacheStatus::Valid);
}

#[test]
fn certificate_rotation_keeps_tls_snapshots_consistent() {
    let temp = Temp::new();
    let target = AcmeTarget {
        domains: vec!["localhost".into()],
        dir: temp.0.clone(),
        cert_path: temp.0.join("cert.pem"),
        key_path: temp.0.join("key.pem"),
    };
    let key1 = rcgen::KeyPair::generate().unwrap();
    let cert1 = rcgen::CertificateParams::new(target.domains.clone())
        .unwrap()
        .self_signed(&key1)
        .unwrap();
    let key2 = rcgen::KeyPair::generate().unwrap();
    let cert2 = rcgen::CertificateParams::new(target.domains.clone())
        .unwrap()
        .self_signed(&key2)
        .unwrap();
    publish_certificate(&target, &cert1.pem(), &key1.serialize_pem()).unwrap();
    let bundle = target.bundle_path().to_str().unwrap().to_owned();
    let tls = crate::config::TlsServerConfig {
        certificate: Some(bundle.clone()),
        private_key: Some(bundle),
        acme: Some(crate::config::TlsAcmeConfig {
            domains: target.domains.clone(),
        }),
    };
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            barrier.wait();
            for i in 0..40 {
                let (cert, key) = if i % 2 == 0 {
                    (cert2.pem(), key2.serialize_pem())
                } else {
                    (cert1.pem(), key1.serialize_pem())
                };
                publish_certificate(&target, &cert, &key).unwrap();
            }
        });
        barrier.wait();
        for _ in 0..80 {
            crate::tls::server_acceptor(&tls).unwrap();
            let hooks = crate::tls::quic_hooks(&tls).unwrap();
            let builder = hooks
                .connection_hook
                .unwrap()
                .create_custom_ssl_context_builder(tokio_quiche::settings::TlsCertificatePaths {
                    cert: tls.certificate_path().unwrap(),
                    private_key: tls.private_key_path().unwrap(),
                    kind: tokio_quiche::settings::CertificateKind::X509,
                });
            assert!(
                builder.is_some(),
                "QUIC reload mixed certificate generations"
            );
        }
    });
    assert_eq!(certificate_cache_status(&target, 30), CacheStatus::Valid);
    assert_eq!(
        std::fs::read_dir(&target.dir).unwrap().count(),
        1,
        "staging files were left behind"
    );
}
