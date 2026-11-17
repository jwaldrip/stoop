use super::expr::{Contexts, Unknowable};

pub fn legs(
    strategy: &serde_json::Value,
    _cx: &dyn Contexts,
) -> Result<Vec<Option<serde_json::Value>>, Unknowable> {
    if strategy.get("matrix").is_some() {
        Err(Unknowable("strategy.matrix is not supported".into()))
    } else if !strategy.is_null() && !strategy.is_object() {
        Err(Unknowable("strategy is not an object".into()))
    } else {
        Ok(vec![None])
    }
}
