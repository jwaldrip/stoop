use super::spec::{Code, JobSpec};
use crate::gha::workflow::Workflow;

fn compact(s: &str) -> String {
    let s = s.trim();
    let s = s
        .strip_prefix("${{")
        .and_then(|s| s.strip_suffix("}}"))
        .unwrap_or(s);
    let mut quoted = false;
    s.chars()
        .filter(|c| {
            if *c == '\'' {
                quoted = !quoted;
            }
            quoted || *c == '\'' || !c.is_whitespace()
        })
        .collect()
}

pub fn check(w: &Workflow, spec: &JobSpec, plan: &str) -> Option<(Code, String)> {
    let jobs = w.root.get("jobs")?.as_object()?;
    if spec.job.is_empty()
        || !spec
            .job
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Some((Code::NotGated, "invalid job id".into()));
    }
    if jobs
        .keys()
        .filter(|id| id.eq_ignore_ascii_case(&spec.job))
        .count()
        != 1
    {
        return Some((Code::NotGated, "job ids collide case-insensitively".into()));
    }
    let expected = format!(
        "!cancelled()&&!contains(needs.{plan}.outputs.skip,',{},')",
        spec.job
    );
    if spec.if_text.as_deref().map(compact).as_deref() != Some(expected.as_str()) {
        return Some((Code::NotGated, "job has no recognized plan gate".into()));
    }
    if spec.needs.len() != 1 || spec.needs[0] != plan {
        return Some((Code::Graph, "job must need only the plan job".into()));
    }
    for (id, job) in jobs {
        if id == &spec.job {
            continue;
        }
        let needs = job.get("needs");
        let depends = needs
            .and_then(|n| n.as_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(&spec.job))
            || needs.and_then(|n| n.as_array()).is_some_and(|ns| {
                ns.iter().any(|n| {
                    n.as_str()
                        .is_some_and(|n| n.eq_ignore_ascii_case(&spec.job))
                })
            });
        if depends {
            return Some((Code::Graph, format!("job {id} needs {}", spec.job)));
        }
    }
    None
}
