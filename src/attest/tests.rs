//! Verifier unit tests. Keys are test-only RSA keys from tests/fixtures/attest; nothing
//! here calls GitHub.

use super::*;
use crate::job::{RecordStatus, StepHow, StepRecord};
use crate::plan::spec::JobSpec;
use ring::rand::SystemRandom;
use serde_json::json;
use std::cell::Cell;
use std::collections::BTreeMap;

pub const JOB: &str = "job-0123456789abcdef0123456789abcdef";
pub const SHA: &str = "3f2c1a9b8e7d6c5b4a39281706f5e4d3c2b1a0f9";
pub const REPO: &str = "owner/repo";
pub const PATH: &str = ".github/workflows/ci.yml";
pub const WORKFLOW: &str = "owner/repo/.github/workflows/ci.yml@refs/heads/main";
pub const KEY_1: &[u8] = include_bytes!("../../tests/fixtures/attest/test-rsa-1.pkcs8.der");
pub const KEY_2: &[u8] = include_bytes!("../../tests/fixtures/attest/test-rsa-2.pkcs8.der");
pub const JWKS: &[u8] = include_bytes!("../../tests/fixtures/attest/test-jwks.json");
const GITHUB_JWKS: &[u8] =
    include_bytes!("../../tests/fixtures/attest/github-jwks-2026-11-17.json");

pub fn pair(der: &[u8]) -> signature::RsaKeyPair {
    signature::RsaKeyPair::from_pkcs8(der).expect("test key")
}

pub fn b64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, byte)| {
            acc | (u32::from(*byte) << (16 - 8 * i))
        });
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// A compact token: the RS256 signature over `header.claims` by `key`.
pub fn token(header: &Value, claims: &Value, key: &signature::RsaKeyPair) -> String {
    let signed = format!(
        "{}.{}",
        b64_encode(&serde_json::to_vec(header).unwrap()),
        b64_encode(&serde_json::to_vec(claims).unwrap())
    );
    let mut sig = vec![0; key.public().modulus_len()];
    key.sign(
        &signature::RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signed.as_bytes(),
        &mut sig,
    )
    .expect("sign");
    format!("{signed}.{}", b64_encode(&sig))
}

pub fn header(kid: &str) -> Value {
    json!({"alg": "RS256", "kid": kid, "typ": "JWT"})
}

/// A job record as the journal publishes it for run 123, attempt 1, at SHA.
pub fn record() -> JobRecord {
    JobRecord {
        created: 1_763_400_000,
        started: 1_763_399_000_000,
        status: Some(RecordStatus::Passed),
        failed: None,
        actions: BTreeMap::new(),
        commit: Some(SHA.into()),
        host: BTreeMap::from([("os".to_string(), "Linux".to_string())]),
        event_path: Some("/runner/_temp/_github_workflow/event.json".into()),
        run: Some("123/1".into()),
        steps: vec![StepRecord {
            key: "sh-aaaaaaaaaaaaaaaaaaaa".into(),
            proof: "p-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            how: StepHow::Ran,
        }],
        attest: None,
        workflow_ref: Some(WORKFLOW.into()),
        job_workflow_ref: None,
    }
}

/// The claims GitHub issues for a push to main that ran `record`.
pub fn claims(record: &JobRecord) -> Value {
    json!({
        "iss": ISSUER,
        "aud": audience(JOB, record).unwrap(),
        "repository": REPO,
        "ref": "refs/heads/main",
        "event_name": "push",
        "sha": SHA,
        "run_id": "123",
        "run_attempt": "1",
        "workflow_ref": WORKFLOW,
        "job_workflow_ref": WORKFLOW,
        "iat": 1_700_000_000u64,
        "nbf": 1_700_000_000u64,
        // Long past: expiry is ignored for historical attestations.
        "exp": 1_700_000_300u64,
    })
}

/// The unsigned `header.claims` of a token for `record` under test-key-1.
pub fn signing_input(record: &JobRecord) -> String {
    format!(
        "{}.{}",
        b64_encode(&serde_json::to_vec(&header("test-key-1")).unwrap()),
        b64_encode(&serde_json::to_vec(&claims(record)).unwrap())
    )
}

/// A token for `record` signed by `key_der` under `kid`, with `edit` applied to its claims.
pub fn signed(
    record: &JobRecord,
    edit: impl FnOnce(&mut Value),
    kid: &str,
    key_der: &[u8],
) -> String {
    let mut claims = claims(record);
    edit(&mut claims);
    token(&header(kid), &claims, &pair(key_der))
}

pub fn spec() -> JobSpec {
    JobSpec {
        workflow: "fixture".into(),
        path: PATH.into(),
        job: "test".into(),
        leg: None,
        key: Some(JOB.into()),
        runs_on: Value::Null,
        needs: vec![],
        if_text: None,
        steps: vec![],
        blocked: None,
    }
}

pub struct Fixed(pub Vec<Key>);

impl KeySource for Fixed {
    fn fetch(&self) -> Result<Vec<Key>, String> {
        Ok(self.0.clone())
    }
}

pub fn published() -> Vec<Key> {
    parse_jwks(JWKS).expect("test JWKS")
}

pub fn verifier() -> Verifier<Fixed> {
    Verifier::new(Policy::default_branch(REPO, "main"), Fixed(published()))
}

pub fn attested(record: &JobRecord, token: String) -> JobRecord {
    let mut attested = record.clone();
    attested.attest = Some(token);
    attested
}

/// The verdict for a published record, asserting that a refusal is `unattested`.
pub fn verdict<S: KeySource>(verifier: &Verifier<S>, published: &JobRecord) -> Result<(), String> {
    verifier
        .check(&spec(), published)
        .map_err(|(code, reason)| {
            assert_eq!(code, Code::Unattested, "{reason}");
            reason
        })
}

fn refused_with<S: KeySource>(verifier: &Verifier<S>, published: &JobRecord, needle: &str) {
    let reason = verdict(verifier, published).expect_err("the record must be refused");
    assert!(
        reason.contains(needle),
        "{reason:?} does not contain {needle:?}"
    );
}

fn unsigned(header: &Value, claims: &Value) -> String {
    format!(
        "{}.{}.",
        b64_encode(&serde_json::to_vec(header).unwrap()),
        b64_encode(&serde_json::to_vec(claims).unwrap())
    )
}

#[test]
fn accepts_a_valid_token_whose_exp_has_passed() {
    let record = record();
    let token = signed(&record, |_| {}, "test-key-1", KEY_1);
    assert_eq!(verdict(&verifier(), &attested(&record, token)), Ok(()));
}

#[test]
fn accepts_job_workflow_ref_equal_to_the_caller_workflow() {
    let mut record = record();
    record.job_workflow_ref = Some(WORKFLOW.into());
    let token = signed(&record, |_| {}, "test-key-1", KEY_1);
    assert_eq!(verdict(&verifier(), &attested(&record, token)), Ok(()));
}

#[test]
fn a_record_without_a_token_is_unattested() {
    assert_eq!(verdict(&verifier(), &record()).unwrap_err(), NO_ATTESTATION);
}

#[test]
fn rejects_alg_none() {
    let record = record();
    let token = unsigned(
        &json!({"alg": "none", "kid": "test-key-1"}),
        &claims(&record),
    );
    refused_with(
        &verifier(),
        &attested(&record, token),
        "algorithm is not RS256",
    );
}

#[test]
fn rejects_hs256_key_confusion() {
    let record = record();
    let key = pair(KEY_1);
    let token = token(
        &json!({"alg": "HS256", "kid": "test-key-1"}),
        &claims(&record),
        &key,
    );
    refused_with(
        &verifier(),
        &attested(&record, token),
        "algorithm is not RS256",
    );
}

#[test]
fn rejects_critical_header_extensions() {
    let record = record();
    let token = token(
        &json!({"alg": "RS256", "kid": "test-key-1", "crit": ["x-unknown"], "x-unknown": true}),
        &claims(&record),
        &pair(KEY_1),
    );
    refused_with(
        &verifier(),
        &attested(&record, token),
        "critical extensions",
    );
}

#[test]
fn rejects_a_kid_that_github_does_not_publish() {
    let record = record();
    let token = signed(&record, |_| {}, "test-key-9", KEY_1);
    refused_with(
        &verifier(),
        &attested(&record, token),
        "no longer published",
    );
}

#[test]
fn rejects_a_key_rotated_out_of_the_jwks() {
    let record = record();
    let token = signed(&record, |_| {}, "test-key-1", KEY_1);
    let only_key_2: Vec<Key> = published()
        .into_iter()
        .filter(|key| key.kid == "test-key-2")
        .collect();
    let verifier = Verifier::new(Policy::default_branch(REPO, "main"), Fixed(only_key_2));
    refused_with(
        &verifier,
        &attested(&record, token),
        "signing key test-key-1 is no longer published",
    );
}

#[test]
fn rejects_a_signature_made_by_another_key_under_a_kid() {
    let record = record();
    let token = signed(&record, |_| {}, "test-key-2", KEY_1);
    refused_with(
        &verifier(),
        &attested(&record, token),
        "signature does not verify",
    );
}

#[test]
fn rejects_an_embedded_jwk_header() {
    let record = record();
    let attacker = published()
        .into_iter()
        .find(|key| key.kid == "test-key-2")
        .unwrap();
    let jwk = json!({"kty": "RSA", "n": b64_encode(&attacker.n), "e": b64_encode(&attacker.e)});
    let token = token(
        &json!({"alg": "RS256", "kid": "test-key-1", "jwk": jwk}),
        &claims(&record),
        &pair(KEY_2),
    );
    refused_with(
        &verifier(),
        &attested(&record, token),
        "signature does not verify",
    );
}

#[test]
fn rejects_a_tampered_payload() {
    let record = record();
    let good = signed(&record, |_| {}, "test-key-1", KEY_1);
    let mut parts: Vec<&str> = good.split('.').collect();
    let mut tampered = claims(&record);
    tampered["ref"] = json!("refs/heads/feature");
    let body = b64_encode(&serde_json::to_vec(&tampered).unwrap());
    parts[1] = body.as_str();
    let token = parts.join(".");
    refused_with(
        &verifier(),
        &attested(&record, token),
        "signature does not verify",
    );
}

#[test]
fn rejects_a_truncated_signature() {
    let record = record();
    // Drop one byte of the real signature and re-encode canonically: the length is wrong,
    // not the encoding.
    let input = signing_input(&record);
    let key = pair(KEY_1);
    let mut sig = vec![0; key.public().modulus_len()];
    key.sign(
        &signature::RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        input.as_bytes(),
        &mut sig,
    )
    .expect("sign");
    let token = format!("{input}.{}", b64_encode(&sig[..sig.len() - 1]));
    refused_with(
        &verifier(),
        &attested(&record, token),
        "signature does not verify",
    );
}

#[test]
fn rejects_a_token_that_is_not_three_segments() {
    let record = record();
    let good = signed(&record, |_| {}, "test-key-1", KEY_1);
    let two = good.rsplit_once('.').unwrap().0.to_string();
    refused_with(&verifier(), &attested(&record, two), "malformed");
}

#[test]
fn rejects_padding_and_foreign_characters() {
    let record = record();
    let good = signed(&record, |_| {}, "test-key-1", KEY_1);
    refused_with(
        &verifier(),
        &attested(&record, format!("{good}=")),
        "malformed",
    );
    let mut foreign = good.clone();
    foreign.replace_range(3..4, "!");
    refused_with(&verifier(), &attested(&record, foreign), "malformed");
}

#[test]
fn rejects_non_canonical_signature_encoding() {
    let record = record();
    let good = signed(&record, |_| {}, "test-key-1", KEY_1);
    // The signature is 256 bytes, so its last character carries four padding bits that
    // a canonical encoding leaves at zero.
    let last = good.chars().last().unwrap();
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let value = alphabet.find(last).unwrap() as u32 ^ 1;
    let replaced = alphabet.as_bytes()[value as usize] as char;
    let token = format!("{}{replaced}", &good[..good.len() - 1]);
    refused_with(&verifier(), &attested(&record, token), "not canonical");
}

#[test]
fn rejects_the_wrong_issuer() {
    let record = record();
    let token = signed(
        &record,
        |c| c["iss"] = json!("https://evil.example"),
        "test-key-1",
        KEY_1,
    );
    refused_with(
        &verifier(),
        &attested(&record, token),
        "issuer is not GitHub Actions",
    );
}

#[test]
fn rejects_a_token_issued_for_another_record() {
    let record = record();
    let mut other = record.clone();
    other.run = Some("456/1".into());
    let token = signed(&other, |c| c["run_id"] = json!("456"), "test-key-1", KEY_1);
    refused_with(
        &verifier(),
        &attested(&record, token),
        "audience does not match this record",
    );
}

#[test]
fn rejects_a_token_replayed_on_another_job() {
    let record = record();
    let token = signed(&record, |_| {}, "test-key-1", KEY_1);
    let published = attested(&record, token);
    let other_job = JobSpec {
        key: Some("job-ffffffffffffffffffffffffffffffff".into()),
        ..spec()
    };
    let reason = verifier()
        .check(&other_job, &published)
        .expect_err("another job must not accept the record");
    assert_eq!(reason.0, Code::Unattested);
    assert!(reason.1.contains("audience does not match"), "{}", reason.1);
}

#[test]
fn rejects_every_altered_record_field() {
    let record = record();
    let token = signed(&record, |_| {}, "test-key-1", KEY_1);
    type Edit = fn(&mut JobRecord);
    let edits: [(&str, Edit); 10] = [
        ("started", |r| r.started += 1),
        ("created", |r| r.created += 1),
        ("status", |r| r.status = Some(RecordStatus::Failed)),
        ("failed", |r| {
            r.failed = Some("sh-cccccccccccccccccccc".into())
        }),
        ("steps", |r| {
            r.steps.push(StepRecord {
                key: "sh-dddddddddddddddddddd".into(),
                proof: "p-e".into(),
                how: StepHow::Skipped,
            })
        }),
        ("step how", |r| r.steps[0].how = StepHow::Skipped),
        ("commit", |r| r.commit = Some("0".repeat(40))),
        ("host", |r| {
            r.host.insert("image_version".into(), "2".into());
        }),
        ("event_path", |r| r.event_path = None),
        ("actions", |r| {
            r.actions.insert("resolved".into(), "x".into());
        }),
    ];
    for (name, edit) in edits {
        let mut published = attested(&record, token.clone());
        edit(&mut published);
        let reason = verdict(&verifier(), &published).expect_err(name);
        assert!(
            reason.contains("audience does not match"),
            "{name}: {reason}"
        );
    }
}

#[test]
fn rejects_another_repository() {
    let record = record();
    let token = signed(
        &record,
        |c| c["repository"] = json!("fork/repo"),
        "test-key-1",
        KEY_1,
    );
    refused_with(
        &verifier(),
        &attested(&record, token),
        "repository fork/repo is not owner/repo",
    );
}

#[test]
fn rejects_refs_that_are_not_the_default_branch() {
    let record = record();
    for git_ref in ["refs/heads/feature", "refs/pull/7/merge", "refs/tags/v1"] {
        let token = signed(&record, |c| c["ref"] = json!(git_ref), "test-key-1", KEY_1);
        refused_with(
            &verifier(),
            &attested(&record, token),
            "is not a trusted branch",
        );
    }
}

#[test]
fn rejects_events_that_run_outside_the_default_branch() {
    let record = record();
    for event in [
        "pull_request",
        "pull_request_target",
        "dynamic",
        "issue_comment",
    ] {
        let token = signed(
            &record,
            |c| c["event_name"] = json!(event),
            "test-key-1",
            KEY_1,
        );
        refused_with(
            &verifier(),
            &attested(&record, token),
            "may not publish job records",
        );
    }
}

#[test]
fn accepts_only_the_trusted_events() {
    let record = record();
    for event in TRUSTED_EVENTS {
        let token = signed(
            &record,
            |c| c["event_name"] = json!(event),
            "test-key-1",
            KEY_1,
        );
        assert_eq!(
            verdict(&verifier(), &attested(&record, token)),
            Ok(()),
            "{event}"
        );
    }
}

#[test]
fn rejects_a_different_commit() {
    let record = record();
    let token = signed(
        &record,
        |c| c["sha"] = json!("1".repeat(40)),
        "test-key-1",
        KEY_1,
    );
    refused_with(&verifier(), &attested(&record, token), "sha does not match");
}

#[test]
fn rejects_another_run_attempt() {
    let record = record();
    let token = signed(
        &record,
        |c| c["run_attempt"] = json!("2"),
        "test-key-1",
        KEY_1,
    );
    refused_with(
        &verifier(),
        &attested(&record, token),
        "run 123/2 does not match",
    );
}

#[test]
fn rejects_a_same_id_job_run_from_a_reusable_workflow() {
    let record = record();
    let shared = "owner/repo/.github/workflows/shared.yml@refs/heads/main";
    let token = signed(
        &record,
        |c| c["job_workflow_ref"] = json!(shared),
        "test-key-1",
        KEY_1,
    );
    refused_with(&verifier(), &attested(&record, token), "reusable workflow");
}

#[test]
fn rejects_a_token_from_another_workflow_file() {
    let record = record();
    let other = "owner/repo/.github/workflows/other.yml@refs/heads/main";
    let token = signed(
        &record,
        |c| {
            c["workflow_ref"] = json!(other);
            c["job_workflow_ref"] = json!(other);
        },
        "test-key-1",
        KEY_1,
    );
    refused_with(
        &verifier(),
        &attested(&record, token),
        "is not the planned job's workflow",
    );
}

#[test]
fn rejects_a_record_whose_workflow_ref_differs_from_the_token() {
    let mut record = record();
    record.workflow_ref = Some("owner/repo/.github/workflows/other.yml@refs/heads/main".into());
    let token = signed(&record, |_| {}, "test-key-1", KEY_1);
    refused_with(
        &verifier(),
        &attested(&record, token),
        "record workflow ref differs",
    );
}

#[test]
fn rejects_a_record_whose_job_workflow_ref_differs_from_the_token() {
    let mut record = record();
    record.job_workflow_ref = Some("owner/repo/.github/workflows/other.yml@refs/heads/main".into());
    let token = signed(&record, |_| {}, "test-key-1", KEY_1);
    refused_with(
        &verifier(),
        &attested(&record, token),
        "record job workflow ref differs",
    );
}

#[test]
fn fetch_failure_is_unattested() {
    struct Down;
    impl KeySource for Down {
        fn fetch(&self) -> Result<Vec<Key>, String> {
            Err("curl failed: Could not resolve host".into())
        }
    }
    let record = record();
    let token = signed(&record, |_| {}, "test-key-1", KEY_1);
    let verifier = Verifier::new(Policy::default_branch(REPO, "main"), Down);
    refused_with(
        &verifier,
        &attested(&record, token),
        "cannot read GitHub's signing keys",
    );
}

#[test]
fn the_key_set_is_fetched_once_per_verifier() {
    struct Counting<'a>(&'a Cell<u32>);
    impl KeySource for Counting<'_> {
        fn fetch(&self) -> Result<Vec<Key>, String> {
            self.0.set(self.0.get() + 1);
            Ok(published())
        }
    }
    let fetches = Cell::new(0);
    let verifier = Verifier::new(Policy::default_branch(REPO, "main"), Counting(&fetches));
    let record = record();
    for _ in 0..3 {
        let token = signed(&record, |_| {}, "test-key-1", KEY_1);
        assert_eq!(verdict(&verifier, &attested(&record, token)), Ok(()));
    }
    assert_eq!(fetches.get(), 1);
}

#[test]
fn parses_github_published_keys() {
    let keys = parse_jwks(GITHUB_JWKS).unwrap();
    assert_eq!(keys.len(), 4);
    assert!(keys
        .iter()
        .any(|key| key.kid == "38E9B30B3A023A1B72309921A69A42FCC496C42C"));
    assert!(keys.iter().all(|key| key.e == [1, 0, 1]));
}

#[test]
fn jwks_rejects_repeated_kids_and_empty_sets() {
    let entry = |kid: &str| json!({"kty": "RSA", "kid": kid, "n": "AQAB", "e": "AQAB"});
    let repeated = json!({"keys": [entry("a"), entry("a")]});
    assert!(parse_jwks(repeated.to_string().as_bytes())
        .unwrap_err()
        .contains("repeats key id a"));
    let none = json!({"keys": [{"kty": "EC", "kid": "e", "crv": "P-256"}]});
    assert!(parse_jwks(none.to_string().as_bytes())
        .unwrap_err()
        .contains("no RSA signing keys"));
    assert!(parse_jwks(b"{}").unwrap_err().contains("no keys array"));
}

#[test]
fn jwks_skips_non_rs256_entries_and_strips_leading_zeros() {
    let document = json!({"keys": [
        {"kty": "RSA", "alg": "PS256", "kid": "pss", "n": "AQAB", "e": "AQAB"},
        {"kty": "RSA", "use": "enc", "kid": "enc", "n": "AQAB", "e": "AQAB"},
        {"kty": "RSA", "kid": "zeros", "n": b64_encode(&[0, 0, 7, 9]), "e": "AQAB"},
    ]});
    let keys = parse_jwks(document.to_string().as_bytes()).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid, "zeros");
    assert_eq!(keys[0].n, vec![7, 9]);
}

#[test]
fn base64url_is_strict() {
    assert_eq!(b64url("AA").unwrap(), vec![0]);
    assert_eq!(b64url("AQAB").unwrap(), vec![1, 0, 1]);
    assert!(b64url("AB").unwrap_err().contains("not canonical"));
    assert!(b64url("A").unwrap_err().contains("malformed"));
    assert!(b64url("AA=").unwrap_err().contains("malformed"));
    assert!(b64url("+/").unwrap_err().contains("malformed"));
}

#[test]
fn encodes_audiences_and_quotes_curl_config() {
    assert_eq!(percent_encode("stoop:r-ab"), "stoop%3Ar-ab");
    assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
}

#[test]
fn digest_covers_the_job_key_and_every_field_but_the_token() {
    let record = record();
    let base = digest(JOB, &record).unwrap();
    assert!(base.starts_with("r-") && base.len() == 34, "{base}");
    let mut with_token = record.clone();
    with_token.attest = Some("x.y.z".into());
    assert_eq!(digest(JOB, &with_token).unwrap(), base);
    assert_ne!(digest("job-other", &record).unwrap(), base);
    let changes: [fn(&mut JobRecord); 11] = [
        |r| r.created += 1,
        |r| r.started += 1,
        |r| r.status = Some(RecordStatus::Running),
        |r| r.failed = Some("sh-x".into()),
        |r| {
            r.actions.insert("a".into(), "b".into());
        },
        |r| r.commit = None,
        |r| {
            r.host.insert("os".into(), "macOS".into());
        },
        |r| r.event_path = None,
        |r| r.run = Some("123/2".into()),
        |r| r.steps[0].key.push('x'),
        |r| r.job_workflow_ref = Some("x".into()),
    ];
    for change in changes {
        let mut changed = record.clone();
        change(&mut changed);
        assert_ne!(digest(JOB, &changed).unwrap(), base);
    }
}

#[test]
fn records_published_before_attestation_still_load_and_are_unattested() {
    let mut value = serde_json::to_value(record()).unwrap();
    value.as_object_mut().unwrap().remove("attest");
    let old: JobRecord = serde_json::from_value(value).unwrap();
    assert_eq!(old.attest, None);
    assert_eq!(verdict(&verifier(), &old).unwrap_err(), NO_ATTESTATION);
}

#[test]
fn policy_trusts_only_the_default_branch() {
    let policy = Policy::default_branch(REPO, "main");
    assert_eq!(policy.refs, ["refs/heads/main"]);
    assert_eq!(policy.events, ["push", "schedule", "workflow_dispatch"]);
}
