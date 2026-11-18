use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unknowable(pub String);
pub trait Contexts {
    fn get(&self, name: &str) -> Result<Value, Unknowable>;
}

pub fn eval_text(t: &str, _cx: &dyn Contexts) -> Result<String, Unknowable> {
    if t.contains("${{") {
        Err(Unknowable("expression in keyed field".into()))
    } else {
        Ok(t.to_string())
    }
}

pub fn eval_value(t: &str, cx: &dyn Contexts) -> Result<Value, Unknowable> {
    Ok(Value::Str(eval_text(t, cx)?))
}

pub fn eval_if(c: &str, _cx: &dyn Contexts, _step: bool) -> Result<bool, Unknowable> {
    match c {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(Unknowable("step if is not a YAML boolean".into())),
    }
}
