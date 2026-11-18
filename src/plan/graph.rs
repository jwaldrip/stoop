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
    if spec.needs.len() != 1 || !spec.needs[0].eq_ignore_ascii_case(plan) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gha::{context::GhCtx, workflow};
    use serde_json::Value;
    use std::collections::BTreeMap;

    fn check_fixture(extra: &str, gate: &str, needs: &str) -> Option<(Code, String)> {
        let text = format!("name: fixture\ndefaults: {{run: {{shell: 'stoop sh {{0}}'}}}}\njobs:\n  p:\n    runs-on: ubuntu-latest\n    steps: []\n  a:\n    needs: {needs}\n    if: \"{gate}\"\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@1111111111111111111111111111111111111111\n      - run: true\n{extra}");
        let workflow = workflow::parse("ci.yml", &text).unwrap();
        let cx = GhCtx::from_parts(BTreeMap::new(), Value::Null);
        let spec = workflow::job_spec(&workflow, &cx, "a", None);
        check(&workflow, &spec, "p")
    }

    #[test]
    fn exact_gate_needs_and_dependents_are_required() {
        let gate = "!cancelled() && !contains(needs.p.outputs.skip, ',a,')";
        assert!(check_fixture("", gate, "[p]").is_none());
        assert_eq!(
            check_fixture("", "!contains(needs.p.outputs.skip, ',a,')", "[p]")
                .unwrap()
                .0,
            Code::NotGated
        );
        assert_eq!(
            check_fixture("", gate, "[p, other]").unwrap().0,
            Code::Graph
        );
        assert_eq!(
            check_fixture(
                "  c:\n    needs: [A]\n    runs-on: ubuntu-latest\n    steps: []\n",
                gate,
                "[p]"
            )
            .unwrap()
            .0,
            Code::Graph
        );
        assert_eq!(
            check_fixture(
                "  A:\n    runs-on: ubuntu-latest\n    steps: []\n",
                gate,
                "[p]"
            )
            .unwrap()
            .0,
            Code::NotGated
        );
    }
}
