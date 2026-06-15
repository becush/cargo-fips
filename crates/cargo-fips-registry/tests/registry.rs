use cargo_fips_registry::{CertificateStatus, ModuleType, Registry};

#[test]
fn builtin_registry_parses() {
    let registry = Registry::builtin().expect("builtin registry should parse");
    assert!(
        !registry.entries().is_empty(),
        "builtin registry should not be empty"
    );
}

#[test]
fn builtin_contains_certificate_4816() {
    let registry = Registry::builtin().expect("builtin registry should parse");
    let entry = registry
        .certificate("4816")
        .expect("certificate #4816 should be present");

    assert_eq!(entry.module.id, "aws-lc-fips");
    assert_eq!(entry.module.module_type, ModuleType::Software);
    assert_eq!(entry.module.security_level, 1);
    assert_eq!(entry.certificate.status, CertificateStatus::Active);
    assert_eq!(entry.certificate.sunset_date.as_deref(), Some("2029-09-30"));
    assert!(entry.validates_version("AWS-LC-FIPS-2.0"));
    assert!(!entry.validates_version("AWS-LC-FIPS-3.0.0"));
    assert!(!entry.binding.approved_algorithms.is_empty());
}

#[test]
fn lookup_by_module_id_and_triple() {
    let registry = Registry::builtin().expect("builtin registry should parse");
    let entry = registry.module("aws-lc-fips").expect("module present");
    assert_eq!(entry.certificate.cmvp_number, "4816");

    let oe = entry
        .tested_oe_for_triple("x86_64-unknown-linux-gnu")
        .expect("x86_64 linux is a tested OE in seed data");
    assert_eq!(oe.os, "Amazon Linux");

    assert!(entry
        .tested_oe_for_triple("riscv64gc-unknown-linux-gnu")
        .is_none());
}

#[test]
fn builtin_contains_wolfcrypt_certs() {
    let registry = Registry::builtin().expect("builtin registry should parse");
    for cert in ["4718", "5041"] {
        let entry = registry
            .certificate(cert)
            .unwrap_or_else(|| panic!("certificate #{cert} should be present"));
        assert_eq!(entry.module.id, "wolfcrypt");
        assert_eq!(entry.module.vendor, "wolfSSL Inc.");
        assert_eq!(entry.module.module_type, ModuleType::Software);
        assert_eq!(entry.certificate.status, CertificateStatus::Active);
        assert!(!entry.binding.approved_algorithms.is_empty());
    }

    let c5041 = registry.certificate("5041").unwrap();
    assert!(c5041.validates_version("wolfCrypt 5.2.0.1"));
    assert_eq!(c5041.certificate.sunset_date.as_deref(), Some("2030-07-17"));
    assert!(c5041
        .tested_oe_for_triple("x86_64-unknown-linux-gnu")
        .is_some());
}

#[test]
fn builtin_contains_openssl_provider() {
    let registry = Registry::builtin().expect("builtin registry should parse");
    let entry = registry
        .certificate("4857")
        .expect("certificate #4857 should be present");
    assert_eq!(entry.module.id, "rhel9-openssl-fips");
    assert_eq!(entry.module.vendor, "Red Hat, Inc.");
    assert_eq!(entry.certificate.status, CertificateStatus::Active);
    assert!(entry.validates_version("3.0.7-395c1a240fbfffd8"));
    // s390x is a tested OE for this certificate.
    assert!(entry
        .tested_oe_for_triple("s390x-unknown-linux-gnu")
        .is_some());
}

#[test]
fn registry_holds_multiple_modules() {
    let registry = Registry::builtin().expect("builtin registry should parse");
    // aws-lc-fips #4816; wolfCrypt #4718 and #5041; RHEL OpenSSL provider #4857.
    assert!(registry.entries().len() >= 4);
}
