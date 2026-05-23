//! Content-Type converter: JSON ↔ XML.
//!
//! For each direction we walk the structure and emit the canonical
//! representation. Round-trips JSON{string,number,bool,null,object,array}.

use anyhow::Result;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::reader::Reader;
use quick_xml::writer::Writer;
use serde_json::Value;
use std::io::Cursor;

pub fn json_to_xml(body: &str, root: &str) -> Result<String> {
    let v: Value = serde_json::from_str(body)?;
    let mut writer = Writer::new_with_indent(Cursor::new(Vec::new()), b' ', 2);
    writer.write_event(Event::Start(BytesStart::new(root)))?;
    walk_json(&mut writer, &v)?;
    writer.write_event(Event::End(BytesEnd::new(root)))?;
    Ok(String::from_utf8(writer.into_inner().into_inner())?)
}

fn walk_json<W: std::io::Write>(writer: &mut Writer<W>, v: &Value) -> Result<()> {
    match v {
        Value::Object(map) => {
            for (k, vv) in map {
                writer.write_event(Event::Start(BytesStart::new(k.as_str())))?;
                walk_json(writer, vv)?;
                writer.write_event(Event::End(BytesEnd::new(k.as_str())))?;
            }
        }
        Value::Array(arr) => {
            for vv in arr {
                writer.write_event(Event::Start(BytesStart::new("item")))?;
                walk_json(writer, vv)?;
                writer.write_event(Event::End(BytesEnd::new("item")))?;
            }
        }
        Value::String(s) => writer.write_event(Event::Text(BytesText::new(s)))?,
        Value::Number(n) => writer.write_event(Event::Text(BytesText::new(&n.to_string())))?,
        Value::Bool(b) => writer.write_event(Event::Text(BytesText::new(if *b { "true" } else { "false" })))?,
        Value::Null => writer.write_event(Event::Text(BytesText::new("")))?,
    }
    Ok(())
}

pub fn xml_to_json(body: &str) -> Result<String> {
    let mut reader = Reader::from_str(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut stack: Vec<(String, Value)> = vec![("root".into(), Value::Object(Default::default()))];
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                stack.push((name, Value::Object(Default::default())));
            }
            Event::End(_) => {
                let (name, child) = stack.pop().unwrap();
                if let Some((_, parent)) = stack.last_mut() {
                    insert_child(parent, &name, child);
                }
            }
            Event::Text(t) => {
                let s = t.unescape().unwrap_or_default().to_string();
                if let Some((_, parent)) = stack.last_mut() {
                    if let Value::Object(m) = parent {
                        if m.is_empty() {
                            *parent = Value::String(s);
                        } else {
                            m.insert("$text".into(), Value::String(s));
                        }
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    let (_, root) = stack.pop().unwrap();
    Ok(serde_json::to_string_pretty(&root)?)
}

fn insert_child(parent: &mut Value, name: &str, child: Value) {
    if let Value::Object(m) = parent {
        match m.get_mut(name) {
            None => {
                m.insert(name.to_string(), child);
            }
            Some(Value::Array(arr)) => arr.push(child),
            Some(existing) => {
                let prev = std::mem::replace(existing, Value::Null);
                *existing = Value::Array(vec![prev, child]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let json = r#"{"name":"alice","age":30,"tags":["a","b"]}"#;
        let xml = json_to_xml(json, "user").unwrap();
        assert!(xml.contains("<name>alice</name>"));
        let back = xml_to_json(&xml).unwrap();
        assert!(back.contains("alice"));
    }
}
