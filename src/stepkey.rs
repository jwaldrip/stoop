pub fn sh_key(
    body: &[u8],
    workflow: &str,
    job: &str,
    cwd_key: &str,
    matrix: Option<&str>,
) -> String {
    let mut h = blake3::Hasher::new();
    h.update(body);
    h.update(workflow.as_bytes());
    h.update(&[0]);
    h.update(job.as_bytes());
    h.update(&[0]);
    h.update(cwd_key.as_bytes());
    if let Some(matrix) = matrix {
        h.update(b"\0matrix\0");
        h.update(matrix.as_bytes());
    }
    format!("sh-{}", &h.finalize().to_hex()[..20])
}

pub fn canonical_matrix(raw: &str) -> Option<String> {
    if raw.trim().is_empty() {
        return None;
    }
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::Null) => None,
        Ok(serde_json::Value::Object(o)) if o.is_empty() => None,
        Ok(value) => Some(value.to_string()),
        Err(e) => {
            eprintln!("stoop: invalid STOOP_MATRIX ({e}); matrix unavailable");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_previous_derivation() {
        let body = b"echo hello\n";
        let mut old = blake3::Hasher::new();
        old.update(body);
        for v in ["workflow", "job"] {
            old.update(v.as_bytes());
            old.update(&[0]);
        }
        old.update(b"src");
        assert_eq!(
            sh_key(body, "workflow", "job", "src", None),
            format!("sh-{}", &old.finalize().to_hex()[..20])
        );
    }
    #[test]
    fn matrix_separates_and_canonicalizes() {
        let a = canonical_matrix("{\"z\": 1, \"a\": {\"y\":2,\"x\":1}}").unwrap();
        let b = canonical_matrix("{\"a\":{\"x\":1,\"y\":2},\"z\":1}").unwrap();
        assert_eq!(a, b);
        assert_ne!(
            sh_key(b"x", "w", "j", "", Some(&a)),
            sh_key(b"x", "w", "j", "", None)
        );
        for v in ["", "null", "{}", "  { }  ", "bad"] {
            assert_eq!(canonical_matrix(v), None);
        }
    }
}
