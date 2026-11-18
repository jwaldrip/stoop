//! Attested job records (decision D1, base spec 3.8).
//!
//! Recording: every published job record carries a GitHub OIDC token whose custom
//! audience is `stoop:<digest>`. The digest covers the job key and the whole record
//! except the token, so a changed field, a record moved to another job, or a token
//! replayed from another record all fail the audience check.
//!
//! Planning: [`Verifier`] accepts a record only when its token verifies against
//! GitHub's published keys and every claim matches the record and the planned job.
//! Anything else is `unattested`, and the job runs.
//!
//! Key lifetime: GitHub documents no retention period for retired signing keys. A
//! record whose key has left the JWKS is `unattested`, so the job runs once and
//! publishes a new record. Issuance time is bounded by the planning ceiling; key
//! retirement can make a record unusable earlier. The JWKS is cached per verifier.

use crate::job::JobRecord;
use crate::plan::spec::{Code, JobSpec, RecordCheck};
use crate::run;
use ring::signature;
use serde_json::Value;
use std::cell::OnceCell;
use std::io::Write;
use std::process::{Command, Stdio};

pub const ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
/// Larger tokens and key sets are refused before they are parsed.
const MAX_TOKEN: usize = 16 * 1024;
const MAX_RESPONSE: &str = "262144";
const MALFORMED: &str = "token is malformed";
const NO_ATTESTATION: &str = "record has no attestation";
/// Events whose runs run on the branch they report. Pull request events run on a
/// merge commit, and pull_request_target runs with the base branch's write access.
pub const TRUSTED_EVENTS: [&str; 3] = ["push", "schedule", "workflow_dispatch"];

/// `r-` plus 32 hex characters: blake3 over the job key, a NUL byte and the record's
/// JSON without its `attest` field. serde_json sorts object keys, so the bytes do not
/// depend on field order.
pub fn digest(job_key: &str, record: &JobRecord) -> Result<String, String> {
    let mut value = serde_json::to_value(record).map_err(|e| e.to_string())?;
    if let Value::Object(fields) = &mut value {
        fields.remove("attest");
    }
    let bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(job_key.as_bytes());
    hasher.update(&[0]);
    hasher.update(&bytes);
    Ok(format!("r-{}", &hasher.finalize().to_hex()[..32]))
}

/// The custom audience a token for this record must carry.
pub fn audience(job_key: &str, record: &JobRecord) -> Result<String, String> {
    Ok(format!("stoop:{}", digest(job_key, record)?))
}

/// Recording side, called when a record is published. The token comes from the runner's
/// OIDC endpoint. Without one the record is published unattested, which planning refuses,
/// so a missing token never fails the step.
pub fn mint(job_key: &str, record: &JobRecord) -> Option<String> {
    // A job without `id-token: write` has no request URL. That is the normal case for a
    // job that does not attest, so it says nothing on every publication.
    run::env_str("ACTIONS_ID_TOKEN_REQUEST_URL")?;
    match mint_token(job_key, record) {
        Ok(token) => Some(token),
        Err(reason) => {
            eprintln!("stoop: sync: job record is unattested: {reason}");
            None
        }
    }
}

fn mint_token(job_key: &str, record: &JobRecord) -> Result<String, String> {
    let url = run::env_str("ACTIONS_ID_TOKEN_REQUEST_URL")
        .ok_or("this job has no OIDC token request URL (grant `id-token: write`)")?;
    let bearer = run::env_str("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .ok_or("this job has no OIDC request token (grant `id-token: write`)")?;
    let audience = audience(job_key, record)?;
    let separator = if url.contains('?') { '&' } else { '?' };
    let url = format!("{url}{separator}audience={}", percent_encode(&audience));
    let body = curl(&url, Some(&bearer))?;
    let response: Value =
        serde_json::from_slice(&body).map_err(|e| format!("OIDC response: {e}"))?;
    let token = response
        .get("value")
        .and_then(Value::as_str)
        .ok_or("OIDC response has no token")?;
    let issued = Token::parse(token)?;
    if issued.claims.get("aud").and_then(Value::as_str) != Some(audience.as_str()) {
        return Err("GitHub issued a token for another audience".into());
    }
    Ok(token.to_string())
}

/// The keys a planner can check a token against, selected by `kid`.
pub trait KeySource {
    fn fetch(&self) -> Result<Vec<Key>, String>;
}

/// GitHub's published key set, fetched over HTTPS.
pub struct Jwks {
    pub url: String,
}

impl KeySource for Jwks {
    fn fetch(&self) -> Result<Vec<Key>, String> {
        parse_jwks(&curl(&self.url, None)?)
    }
}

/// One RSA signing key from a JWKS.
#[derive(Clone, Debug)]
pub struct Key {
    kid: String,
    n: Vec<u8>,
    e: Vec<u8>,
}

impl Key {
    fn verifies(&self, signed: &str, signature_bytes: &[u8]) -> bool {
        signature::RsaPublicKeyComponents {
            n: self.n.as_slice(),
            e: self.e.as_slice(),
        }
        .verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            signed.as_bytes(),
            signature_bytes,
        )
        .is_ok()
    }
}

/// RSA keys from a JWKS. Entries that are not RS256 signing keys are skipped. A repeated
/// key id is an error, because it would make the key used for a token ambiguous.
pub fn parse_jwks(bytes: &[u8]) -> Result<Vec<Key>, String> {
    let document: Value = serde_json::from_slice(bytes).map_err(|e| format!("JWKS: {e}"))?;
    let entries = document
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("JWKS has no keys array")?;
    let mut keys: Vec<Key> = Vec::new();
    for entry in entries {
        if entry.get("kty").and_then(Value::as_str) != Some("RSA") {
            continue;
        }
        if entry
            .get("alg")
            .is_some_and(|alg| alg.as_str() != Some("RS256"))
            || entry
                .get("use")
                .is_some_and(|usage| usage.as_str() != Some("sig"))
        {
            continue;
        }
        let kid = entry
            .get("kid")
            .and_then(Value::as_str)
            .filter(|kid| !kid.is_empty())
            .ok_or("JWKS RSA key has no kid")?;
        if keys.iter().any(|key| key.kid == kid) {
            return Err(format!("JWKS repeats key id {kid}"));
        }
        let member = |name: &str| {
            entry
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("JWKS key {kid} has no {name}"))
        };
        let n = b64url(member("n")?)?;
        let start = n.iter().position(|byte| *byte != 0).unwrap_or(n.len());
        keys.push(Key {
            kid: kid.into(),
            n: n[start..].to_vec(),
            e: b64url(member("e")?)?,
        });
    }
    if keys.is_empty() {
        return Err("JWKS has no RSA signing keys".into());
    }
    Ok(keys)
}

/// What a token must match besides its signature.
#[derive(Clone, Debug)]
pub struct Policy {
    pub repository: String,
    pub repository_id: String,
    pub repository_owner_id: String,
    /// Full refs whose runs may publish, for example `refs/heads/main`.
    pub refs: Vec<String>,
    pub events: Vec<String>,
}

impl Policy {
    /// Only runs on the default branch, from the events in [`TRUSTED_EVENTS`], may publish.
    pub fn default_branch(
        repository: &str,
        repository_id: &str,
        repository_owner_id: &str,
        branch: &str,
    ) -> Self {
        Self {
            repository: repository.into(),
            repository_id: repository_id.into(),
            repository_owner_id: repository_owner_id.into(),
            refs: vec![format!("refs/heads/{branch}")],
            events: TRUSTED_EVENTS
                .iter()
                .map(|event| event.to_string())
                .collect(),
        }
    }
}

/// Planner side. The GitHub key set is fetched once, when the first record is checked.
pub struct Verifier<S: KeySource> {
    policy: Policy,
    source: S,
    now: u64,
    ceiling: u64,
    keys: OnceCell<Result<Vec<Key>, String>>,
}

/// A verifier that reads GitHub's published keys.
pub fn github(policy: Policy, now: u64, ceiling: u64) -> Verifier<Jwks> {
    Verifier::new(
        policy,
        Jwks {
            url: JWKS_URL.into(),
        },
        now,
        ceiling,
    )
}

impl<S: KeySource> Verifier<S> {
    pub fn new(policy: Policy, source: S, now: u64, ceiling: u64) -> Self {
        Self {
            policy,
            source,
            now,
            ceiling,
            keys: OnceCell::new(),
        }
    }

    fn keys(&self) -> Result<&[Key], String> {
        match self.keys.get_or_init(|| self.source.fetch()) {
            Ok(keys) => Ok(keys.as_slice()),
            Err(error) => Err(format!("cannot read GitHub's signing keys: {error}")),
        }
    }

    fn check_record(
        &self,
        job_key: &str,
        path: &str,
        record: &JobRecord,
    ) -> Result<VerifiedAttestation, String> {
        let token = Token::parse(record.attest.as_deref().ok_or(NO_ATTESTATION)?)?;
        if token.header.get("alg").and_then(Value::as_str) != Some("RS256") {
            return Err("token algorithm is not RS256".into());
        }
        if token.header.get("crit").is_some() {
            return Err("token declares critical extensions".into());
        }
        // A token may name only the key set GitHub publishes. A header that carries or
        // points to a key is refused, not ignored.
        if ["jwk", "jku", "x5u", "x5c"]
            .iter()
            .any(|name| token.header.get(*name).is_some())
        {
            return Err(
                "token declares its own key; only GitHub's published key set is trusted".into(),
            );
        }
        let kid = token
            .header
            .get("kid")
            .and_then(Value::as_str)
            .filter(|kid| !kid.is_empty())
            .ok_or("token has no key id")?;
        let key = self
            .keys()?
            .iter()
            .find(|key| key.kid == kid)
            .ok_or_else(|| {
                format!(
                    "signing key {kid} is no longer published by GitHub; the record is unattested"
                )
            })?;
        if !key.verifies(token.signed, &token.signature) {
            return Err("token signature does not verify".into());
        }
        // The claims are read only after the signature has verified.
        self.check_claims(job_key, path, record, &token.claims)
    }

    fn check_claims(
        &self,
        job_key: &str,
        path: &str,
        record: &JobRecord,
        claims: &Value,
    ) -> Result<VerifiedAttestation, String> {
        let text = |name: &str| claims.get(name).and_then(Value::as_str);
        if text("iss") != Some(ISSUER) {
            return Err("token issuer is not GitHub Actions".into());
        }
        let audience = audience(job_key, record)?;
        if text("aud") != Some(audience.as_str()) {
            return Err("audience does not match this record: it was changed, or its token belongs to another record".into());
        }
        let repository = self.policy.repository.as_str();
        if text("repository") != Some(repository) {
            return Err(format!(
                "repository {} is not {repository}",
                text("repository").unwrap_or("(none)")
            ));
        }
        for (name, expected) in [
            ("repository_id", &self.policy.repository_id),
            ("repository_owner_id", &self.policy.repository_owner_id),
        ] {
            if expected.is_empty() || text(name) != Some(expected.as_str()) {
                return Err(format!("{name} does not match the trusted repository"));
            }
        }
        if text("runner_environment") != Some("github-hosted") {
            return Err("runner is not GitHub-hosted".into());
        }
        if text("ref_protected") != Some("true") {
            return Err("branch is not protected".into());
        }
        let iat = claims
            .get("iat")
            .and_then(Value::as_u64)
            .ok_or("token has no integer iat")?;
        if self.ceiling == 0 {
            return Err("plan ceiling must be greater than zero".into());
        }
        if iat > self.now.saturating_add(300) || self.now.saturating_sub(iat) > self.ceiling {
            return Err("token issue time is outside the plan window".into());
        }
        let nbf = claims
            .get("nbf")
            .and_then(Value::as_u64)
            .ok_or("token has no integer nbf")?;
        if nbf > self.now.saturating_add(300) {
            return Err("token is not yet valid".into());
        }
        if record.started > iat.saturating_add(300).saturating_mul(1000) {
            return Err("record starts after its token was issued".into());
        }
        let git_ref = text("ref").ok_or("token has no ref")?;
        if !self.policy.refs.iter().any(|allowed| allowed == git_ref) {
            return Err(format!("ref {git_ref} is not a trusted branch"));
        }
        let event = text("event_name").ok_or("token has no event name")?;
        if !self.policy.events.iter().any(|allowed| allowed == event) {
            return Err(format!("event {event} may not publish job records"));
        }
        let commit = record.commit.as_deref().ok_or("record has no commit")?;
        if text("sha") != Some(commit) {
            return Err("sha does not match the record's commit".into());
        }
        let run = record.run.as_deref().ok_or("record has no run")?;
        let token_run = format!(
            "{}/{}",
            number(claims, "run_id")?,
            number(claims, "run_attempt")?
        );
        if token_run != run {
            return Err(format!(
                "run {token_run} does not match the record's run {run}"
            ));
        }
        let workflow = format!("{repository}/{path}@{git_ref}");
        let workflow_ref = text("workflow_ref").ok_or("token has no workflow ref")?;
        if workflow_ref != workflow {
            return Err(format!(
                "workflow {workflow_ref} is not the planned job's workflow {workflow}"
            ));
        }
        // GITHUB_WORKFLOW_REF names the caller of a reusable workflow. The job_workflow_ref
        // claim names the file that ran the job, so a job from a called workflow with the
        // planned job's id is refused.
        let job_ref = match claims.get("job_workflow_ref") {
            None => workflow_ref,
            Some(Value::String(job_ref)) => job_ref.as_str(),
            Some(_) => return Err(MALFORMED.into()),
        };
        if job_ref != workflow_ref {
            return Err(format!(
                "job ran in reusable workflow {job_ref}, which the planned job does not name"
            ));
        }
        if record.workflow_ref.as_deref() != Some(workflow_ref) {
            return Err("record workflow ref differs from the token".into());
        }
        if record
            .job_workflow_ref
            .as_deref()
            .is_some_and(|recorded| recorded != job_ref)
        {
            return Err("record job workflow ref differs from the token".into());
        }
        Ok(VerifiedAttestation { iat })
    }
}

/// Authenticated issuance time. For each proof use `now - min(proof.created, iat)`
/// when enforcing that step's maximum age. Obtain only via `verify`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedAttestation {
    iat: u64,
}

impl VerifiedAttestation {
    pub fn iat(&self) -> u64 {
        self.iat
    }
}

impl<S: KeySource> Verifier<S> {
    pub fn verify(
        &self,
        spec: &JobSpec,
        record: &JobRecord,
    ) -> Result<VerifiedAttestation, (Code, String)> {
        let job_key = spec
            .key
            .as_deref()
            .ok_or((Code::Unattested, "job has no key".into()))?;
        self.check_record(job_key, &spec.path, record)
            .map_err(|reason| (Code::Unattested, reason))
    }
}
impl<S: KeySource> RecordCheck for Verifier<S> {
    fn check(&self, spec: &JobSpec, record: &JobRecord) -> Result<(), (Code, String)> {
        self.verify(spec, record).map(|_| ())
    }
}

/// A compact JWS whose parts have been decoded but whose signature has not been checked.
struct Token<'a> {
    header: Value,
    claims: Value,
    signed: &'a str,
    signature: Vec<u8>,
}

impl<'a> Token<'a> {
    fn parse(text: &'a str) -> Result<Self, String> {
        if text.len() > MAX_TOKEN {
            return Err("token is too large".into());
        }
        let mut parts = text.split('.');
        let (Some(head), Some(body), Some(sig), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(MALFORMED.into());
        };
        Ok(Self {
            header: json_object(&b64url(head)?)?,
            claims: json_object(&b64url(body)?)?,
            signed: &text[..head.len() + 1 + body.len()],
            signature: b64url(sig)?,
        })
    }
}

fn json_object(bytes: &[u8]) -> Result<Value, String> {
    match serde_json::from_slice::<Value>(bytes) {
        Ok(value) if value.is_object() => Ok(value),
        _ => Err(MALFORMED.into()),
    }
}

fn number(claims: &Value, name: &str) -> Result<String, String> {
    match claims.get(name) {
        Some(Value::String(text)) => Ok(text.clone()),
        Some(Value::Number(number)) => Ok(number.to_string()),
        _ => Err(format!("token has no {name}")),
    }
}

/// Strict base64url without padding. Non-canonical trailing bits are refused, so each
/// token has exactly one encoding.
fn b64url(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 4 == 1 {
        return Err(MALFORMED.into());
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(MALFORMED.into()),
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return Err("token encoding is not canonical".into());
    }
    Ok(out)
}

fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

/// Quotes a value for a curl config file.
fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// One HTTPS GET with curl. The URL and the bearer token go over stdin, so the token
/// never appears in the process list.
fn curl(url: &str, bearer: Option<&str>) -> Result<Vec<u8>, String> {
    if url.contains(['\n', '\r']) {
        return Err("URL contains a line break".into());
    }
    let mut config = format!(
        "url = {}\nheader = \"Accept: application/json\"\n",
        quote(url)
    );
    if let Some(bearer) = bearer {
        if bearer.contains(['\n', '\r']) {
            return Err("request token contains a line break".into());
        }
        config.push_str(&format!(
            "header = {}\n",
            quote(&format!("Authorization: bearer {bearer}"))
        ));
    }
    let mut child = curl_command(url)
        .spawn()
        .map_err(|e| format!("cannot run curl: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(config.as_bytes())
            .map_err(|e| format!("curl: {e}"))?;
    }
    let output = child.wait_with_output().map_err(|e| format!("curl: {e}"))?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    let error = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "curl failed: {}",
        error.lines().next().unwrap_or("no output").trim()
    ))
}

fn curl_command(url: &str) -> Command {
    let mut command = Command::new("curl");
    command
        .args([
            "-q",
            "--proto",
            if cfg!(test) && url.starts_with("http://127.0.0.1:") {
                "=http,https"
            } else {
                "=https"
            },
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "30",
            "--max-filesize",
            MAX_RESPONSE,
            "--config",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod e2e;
