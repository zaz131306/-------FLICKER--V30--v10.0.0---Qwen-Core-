//! Minimal JSON value model with a *canonical* serializer and a small
//! recursive-descent parser.
//!
//! Canonical form (normative — the Python reference implementation MUST
//! match byte-for-byte, see tests/vectors/canon.json):
//! * objects: keys sorted bytewise ascending, no duplicate keys;
//! * separators: `,` and `:` with no whitespace;
//! * strings: minimal escaping — `"` `\` `\b` `\f` `\n` `\r` `\t` and
//!   `\u00xx` (lowercase hex) for other control bytes < 0x20; all other
//!   Unicode passes through as raw UTF-8;
//! * numbers: integers only (i64), rendered in decimal, no leading zeros.
//!   Floating point is rejected by the canonical serializer — replay
//!   payloads must be deterministic across languages.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::error::{FlickerError, FlickerResult};

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn obj() -> Json {
        Json::Obj(BTreeMap::new())
    }
    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }
    pub fn int(i: i64) -> Json {
        Json::Int(i)
    }
    pub fn arr(v: Vec<Json>) -> Json {
        Json::Arr(v)
    }

    /// Builder helper: insert into an object (panics-free; ignores non-objects).
    pub fn insert(&mut self, key: &str, value: Json) -> &mut Json {
        if let Json::Obj(map) = self {
            map.insert(key.to_string(), value);
        }
        self
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(map) => map.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Json::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&Vec<Json>> {
        match self {
            Json::Arr(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Canonical serialization (normative; see module docs).
    pub fn to_canonical(&self) -> FlickerResult<String> {
        let mut out = String::new();
        self.write_canonical(&mut out)?;
        Ok(out)
    }

    fn write_canonical(&self, out: &mut String) -> FlickerResult<()> {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Int(i) => {
                let _ = write!(out, "{}", i);
            }
            Json::Str(s) => write_json_string(out, s),
            Json::Arr(items) => {
                out.push('[');
                for (idx, item) in items.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    item.write_canonical(out)?;
                }
                out.push(']');
            }            Json::Obj(map) => {
                out.push('{');
                for (idx, (k, v)) in map.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    write_json_string(out, k);
                    out.push(':');
                    v.write_canonical(out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }

    /// Pretty (non-normative) rendering for humans/logs.
    pub fn to_pretty(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out
    }

    fn write_pretty(&self, out: &mut String, indent: usize) {
        let pad = "  ".repeat(indent);
        let pad2 = "  ".repeat(indent + 1);
        match self {
            Json::Obj(map) if !map.is_empty() => {
                out.push_str(&pad);
                out.push_str("{\n");
                let n = map.len();
                for (i, (k, v)) in map.iter().enumerate() {
                    out.push_str(&pad2);
                    write_json_string(out, k);
                    out.push_str(": ");
                    let mut sub = String::new();
                    v.write_pretty(&mut sub, indent + 1);
                    out.push_str(sub.trim_start());
                    if i + 1 < n {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push('}');
            }
            Json::Arr(items) if !items.is_empty() => {
                out.push_str(&pad);
                out.push_str("[\n");
                let n = items.len();
                for (i, v) in items.iter().enumerate() {
                    let mut sub = String::new();
                    v.write_pretty(&mut sub, indent + 1);
                    out.push_str(&sub);
                    if i + 1 < n {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push(']');
            }
            _ => {
                let mut tmp = String::new();
                // scalars/empty containers: canonical is fine for pretty too
                let _ = self.write_canonical_into(&mut tmp);
                out.push_str(&pad);
                out.push_str(&tmp);
            }
        }
    }

    fn write_canonical_into(&self, out: &mut String) -> FlickerResult<()> {
        self.write_canonical(out)
    }
}

fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

pub fn parse_json(input: &str) -> FlickerResult<Json> {
    let mut p = Parser { chars: input.as_bytes(), pos: 0, src: input };
    p.skip_ws();
    let v = p.parse_value()?;
    p.skip_ws();
    if p.pos != p.chars.len() {
        return Err(p.err("trailing characters after JSON value"));
    }
    Ok(v)
}

struct Parser<'a> {
    chars: &'a [u8],
    src: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, msg: &str) -> FlickerError {
        let upto = &self.src[..self.pos.min(self.src.len())];
        let line = upto.matches('\n').count() + 1;
        let col = match upto.rfind('\n') {
            Some(i) => upto.len() - i,
            None => upto.chars().count() + 1,
        };
        FlickerError::at("parse", format!("JSON: {} ", msg), crate::error::Pos { line, col })
    }

    fn peek(&self) -> Option<u8> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, c: u8) -> FlickerResult<()> {
        self.skip_ws();
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(&format!("expected '{}'", c as char)))
        }
    }

    fn parse_value(&mut self) -> FlickerResult<Json> {
        self.skip_ws();
        match self.peek() {
            None => Err(self.err("unexpected end of input")),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Json::Str(self.parse_string()?)),
            Some(b't') => self.parse_literal("true", Json::Bool(true)),
            Some(b'f') => self.parse_literal("false", Json::Bool(false)),
            Some(b'n') => self.parse_literal("null", Json::Null),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(_) => Err(self.err("unexpected character")),
        }
    }

    fn parse_literal(&mut self, lit: &str, value: Json) -> FlickerResult<Json> {
        if self.src[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(value)
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn parse_object(&mut self) -> FlickerResult<Json> {
        self.expect(b'{')?;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(map));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.expect(b':')?;
            let v = self.parse_value()?;
            map.insert(key, v);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => return Err(self.err("expected ',' or '}' in object")),
            }
        }
        Ok(Json::Obj(map))
    }

    fn parse_array(&mut self) -> FlickerResult<Json> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            let v = self.parse_value()?;
            items.push(v);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => break,
                _ => return Err(self.err("expected ',' or ']' in array")),
            }
        }
        Ok(Json::Arr(items))
    }

    fn parse_string(&mut self) -> FlickerResult<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err(self.err("unterminated string")),
                Some(b'"') => break,
                Some(b'\\') => match self.bump() {
                    Some(b'"') => out.push('"'),
                    Some(b'\\') => out.push('\\'),
                    Some(b'/') => out.push('/'),
                    Some(b'n') => out.push('\n'),
                    Some(b'r') => out.push('\r'),
                    Some(b't') => out.push('\t'),
                    Some(b'b') => out.push('\u{08}'),
                    Some(b'f') => out.push('\u{0c}'),
                    Some(b'u') => {
                        let mut cp = 0u32;
                        for _ in 0..4 {
                            let d = self
                                .bump()
                                .and_then(|b| (b as char).to_digit(16))
                                .ok_or_else(|| self.err("bad \\u escape"))?;
                            cp = cp * 16 + d;
                        }
                        // Surrogate pairs: decode minimally.
                        if (0xd800..0xdc00).contains(&cp) {
                            if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                                return Err(self.err("expected low surrogate"));
                            }
                            let mut lo = 0u32;
                            for _ in 0..4 {
                                let d = self
                                    .bump()
                                    .and_then(|b| (b as char).to_digit(16))
                                    .ok_or_else(|| self.err("bad \\u escape"))?;
                                lo = lo * 16 + d;
                            }
                            if !(0xdc00..0xe000).contains(&lo) {
                                return Err(self.err("bad low surrogate"));
                            }
                            let c = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                            out.push(char::from_u32(c).unwrap_or('\u{fffd}'));
                        } else {
                            out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                        }
                    }
                    _ => return Err(self.err("invalid escape")),
                },
                Some(b) => {
                    // Re-decode the UTF-8 sequence starting at b.
                    self.pos -= 1;
                    let rest = &self.src[self.pos..];
                    let ch = rest
                        .chars()
                        .next()
                        .ok_or_else(|| self.err("invalid utf-8"))?;
                    if (ch as u32) < 0x20 {
                        return Err(self.err("raw control byte in string"));
                    }
                    out.push(ch);
                    self.pos += ch.len_utf8();
                    let _ = b;
                }
            }
        }
        Ok(out)
    }

    fn parse_number(&mut self) -> FlickerResult<Json> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        let text = &self.src[start..self.pos];
        // Integers only in canonical model; reject float syntax loudly.
        if let Some(b) = self.peek() {
            if b == b'.' || b == b'e' || b == b'E' {
                return Err(self.err("floating point numbers are not allowed (canonical JSON)"));
            }
        }
        if text.is_empty() || text == "-" {
            return Err(self.err("invalid number"));
        }
        text.parse::<i64>()
            .map(Json::Int)
            .map_err(|_| self.err("number out of i64 range"))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn canonical_sorted_keys_compact() {
        let mut o = Json::obj();
        o.insert("b", Json::int(2));
        o.insert("a", Json::str("x"));
        o.insert("c", Json::arr(vec![Json::Bool(true), Json::Null]));
        assert_eq!(o.to_canonical().expect("canon"), r#"{"a":"x","b":2,"c":[true,null]}"#);
    }

    #[test]
    fn escapes() {
        let s = Json::str("a\"b\\c\nd\te\u{1}ж");
        assert_eq!(
            s.to_canonical().expect("canon"),
            "\"a\\\"b\\\\c\\nd\\te\\u0001ж\""
        );
    }

    #[test]
    fn parse_roundtrip() {
        // `Json::Obj` is a BTreeMap on purpose: canonical key order is what makes
        // `event_hash` in the replay chain stable (G3/G4). Serialization must
        // therefore SORT keys, not preserve input order. The previous version of
        // this test asserted input-order preservation, which contradicts that
        // requirement — a payload built in a different order would hash
        // differently and break chain verification.
        let src = r#"{"x":[1,-2,{"y":"z"}],"n":null,"t":true,"f":false}"#;
        let expected_canonical =
            r#"{"f":false,"n":null,"t":true,"x":[1,-2,{"y":"z"}]}"#;

        let v = parse_json(src).expect("parse");
        let canon = v.to_canonical().expect("canon");
        assert_eq!(canon, expected_canonical, "keys must be sorted canonically");

        // Idempotency: canonical form is a fixed point of parse -> serialize.
        let v2 = parse_json(&canon).expect("reparse");
        assert_eq!(v2.to_canonical().expect("canon2"), canon);
        assert_eq!(v, v2, "parse(canonical(x)) must equal x");
    }

    #[test]
    fn key_order_does_not_affect_canonical_form() {
        // Directly pins the determinism property the replay chain relies on:
        // two documents differing only in key order canonicalize identically.
        let a = parse_json(r#"{"p":1,"q":2,"r":3}"#).expect("a");
        let b = parse_json(r#"{"r":3,"p":1,"q":2}"#).expect("b");
        assert_eq!(
            a.to_canonical().expect("ca"),
            b.to_canonical().expect("cb"),
            "key order must not change the canonical form"
        );
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_floats() {
        assert!(parse_json("1.5").is_err());
        assert!(parse_json("1e3").is_err());
    }

    #[test]
    fn rejects_trailing() {
        assert!(parse_json("{} x").is_err());
    }

    #[test]
    fn unicode_escape_roundtrip() {
        let v = parse_json(r#""\u0416\u00e9""#).expect("parse");
        assert_eq!(v.as_str().expect("str"), "Жé");
    }
}
