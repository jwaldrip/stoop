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
