pub fn sh_key(
    body: &[u8],
    workflow: &str,
    job: &str,
    cwd_key: &str,
    args: &[std::ffi::OsString],
    matrix: Option<&str>,
) -> String {
    let mut h = blake3::Hasher::new();
    for field in [
        body,
        workflow.as_bytes(),
        job.as_bytes(),
        cwd_key.as_bytes(),
    ]
    .into_iter()
    .chain(args.iter().map(|arg| arg.as_encoded_bytes()))
    {
        h.update(&(field.len() as u64).to_le_bytes());
        h.update(field);
    }
    if let Some(matrix) = matrix {
        h.update(b"\0matrix\0");
        h.update(matrix.as_bytes());
    }
    format!("sh-{}", &h.finalize().to_hex()[..20])
}

/// Apply the repository identity used when a proof store is shared across roots.
pub fn scoped(key: &str, scope: Option<&str>) -> String {
    let Some(scope) = scope else {
        return key.to_string();
    };
    let mut h = blake3::Hasher::new();
    h.update(key.as_bytes());
    h.update(&[0]);
    h.update(scope.as_bytes());
    format!("sh-{}", &h.finalize().to_hex()[..20])
}

pub fn canonical_matrix(raw: &str) -> Result<Option<String>, String> {
    if raw.trim().is_empty() {
        return Ok(None);
    }
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::Null) => Ok(None),
        Ok(serde_json::Value::Object(o)) if o.is_empty() => Ok(None),
        Ok(value) => Ok(Some(value.to_string())),
        Err(e) => Err(format!("invalid STOOP_MATRIX: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_cwd_and_argument_derivation() {
        let body = b"echo hello\n";
        let args = vec![std::ffi::OsString::from("argument")];
        let mut expected = blake3::Hasher::new();
        for field in [body.as_slice(), b"workflow", b"job", b"src", b"argument"] {
            expected.update(&(field.len() as u64).to_le_bytes());
            expected.update(field);
        }
        assert_eq!(
            sh_key(body, "workflow", "job", "src", &args, None),
            format!("sh-{}", &expected.finalize().to_hex()[..20])
        );
        assert_ne!(
            sh_key(body, "workflow", "job", "src", &args, None),
            sh_key(body, "workflow", "job", "src", &[], None)
        );
    }
    #[test]
    fn matrix_separates_and_canonicalizes() {
        let a = canonical_matrix("{\"z\": 1, \"a\": {\"y\":2,\"x\":1}}")
            .unwrap()
            .unwrap();
        let b = canonical_matrix("{\"a\":{\"x\":1,\"y\":2},\"z\":1}")
            .unwrap()
            .unwrap();
        assert_eq!(a, b);
        assert_ne!(
            sh_key(b"x", "w", "j", "", &[], Some(&a)),
            sh_key(b"x", "w", "j", "", &[], None)
        );
        for v in ["", "null", "{}", "  { }  "] {
            assert_eq!(canonical_matrix(v).unwrap(), None);
        }
        assert!(canonical_matrix("bad").is_err());
    }
}

#[cfg(test)]
mod non_utf8_args {
    use super::sh_key;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn non_utf8_arguments_are_keyed_by_their_exact_bytes() {
        let fe = [OsString::from_vec(b"\xfe".to_vec())];
        let ff = [OsString::from_vec(b"\xff".to_vec())];
        assert_ne!(
            sh_key(b"echo", "workflow", "job", "src", &fe, None),
            sh_key(b"echo", "workflow", "job", "src", &ff, None)
        );
    }
}
