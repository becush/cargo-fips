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

    assert!(entry.tested_oe_for_triple("riscv64gc-unknown-linux-gnu").is_none());
}
