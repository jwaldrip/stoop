use super::spec::Decision;
use serde_json::{json, Value};
use std::io::Write;

pub fn escape(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

pub fn job(id: &str, gated: bool, decision: &Decision, key: Option<&str>) -> Value {
    let evidence = decision.evidence.as_ref();
    let leg = json!({"matrix": null, "key": key, "decision": if decision.skip {"skip"} else {"run"},
        "code": decision.code, "detail": decision.detail,
        "record": evidence.map(|e| json!({"run": e.run, "created": e.created, "commit": e.commit})),
        "checked": evidence.map(|e| json!({"steps":e.steps,"inputs":e.inputs,"priors":e.priors,"hashed":e.hashed,"by_diff":e.by_diff,"overlay":e.overlay})),
        "assumed": evidence.map(|e| json!({"outside_inputs":e.assumed_outside,"env":e.assumed_env})),
        "mismatch": decision.mismatches.first().map(|(step,path,why)| json!({"step":step,"path":path,"why":why}))});
    json!({"id":id,"gated":gated,"decision":if decision.skip {"skip"} else {"run"},"code":decision.code,"detail":decision.detail,"legs":[leg]})
}

pub fn emit(
    plan: &Value,
    format: &str,
    dest: Option<&str>,
    quiet: bool,
    warning: Option<&str>,
) -> Result<(), String> {
    let json = serde_json::to_string_pretty(plan).map_err(|e| e.to_string())?;
    if !quiet {
        if let Some(jobs) = plan["jobs"].as_array() {
            for job in jobs {
                let detail = if job["decision"] == "skip" {
                    "proved".to_string()
                } else if let Some(m) = job["legs"][0]["mismatch"].as_object() {
                    format!(
                        "{} {} (step {})",
                        m["path"].as_str().unwrap_or("?"),
                        m["why"].as_str().unwrap_or("changed"),
                        m["step"]
                    )
                } else {
                    job["detail"].as_str().unwrap_or("error").to_string()
                };
                eprintln!(
                    "stoop: {} {}: {}",
                    escape(job["decision"].as_str().unwrap_or("run")),
                    escape(job["id"].as_str().unwrap_or("?")),
                    escape(&detail)
                );
            }
        }
    }
    if let Some(warning) = warning {
        eprintln!("::warning::stoop plan: {}; every job runs", escape(warning));
    }
    let output = match format {
        "github" => {
            let skips = plan["skip"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            let mut out = format!(
                "skip=,{}",
                if skips.is_empty() {
                    String::new()
                } else {
                    format!("{},", skips.join(","))
                }
            );
            out.push('\n');
            if json.len() <= 900 * 1024 {
                use ring::rand::SecureRandom;
                let mut random = [0u8; 8];
                if ring::rand::SystemRandom::new().fill(&mut random).is_ok() {
                    let delimiter = format!("STOOP_PLAN_{:016x}", u64::from_be_bytes(random));
                    out.push_str(&format!("plan<<{delimiter}\n{json}\n{delimiter}\n"));
                } else {
                    eprintln!(
                        "::warning::stoop plan: random delimiter unavailable; plan output omitted"
                    );
                }
            } else {
                eprintln!("::warning::stoop plan: JSON exceeds 900 KiB; plan output omitted");
            }
            if let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
                let mut summary =
                    String::from("| Job | Decision | Code | Detail |\n| --- | --- | --- | --- |\n");
                for j in plan["jobs"].as_array().into_iter().flatten() {
                    let cell = |key: &str| {
                        j[key]
                            .as_str()
                            .unwrap_or("")
                            .replace('|', "\\|")
                            .replace(['\n', '\r'], " ")
                    };
                    summary.push_str(&format!(
                        "| {} | {} | {} | {} |\n",
                        cell("id"),
                        cell("decision"),
                        cell("code"),
                        cell("detail")
                    ));
                }
                if let Err(e) = append(&path, &summary) {
                    eprintln!("::warning::stoop plan: summary: {}", escape(&e));
                }
            }
            out
        }
        "json" => format!("{json}\n"),
        _ => String::new(),
    };
    if let Some(path) = dest {
        std::fs::write(path, &output).map_err(|e| e.to_string())
    } else if let Some(path) = (format == "github")
        .then(|| std::env::var("GITHUB_OUTPUT").ok())
        .flatten()
    {
        append(&path, &output)
    } else {
        print!("{output}");
        Ok(())
    }
}
fn append(path: &str, text: &str) -> Result<(), String> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .map_err(|e| e.to_string())
}
