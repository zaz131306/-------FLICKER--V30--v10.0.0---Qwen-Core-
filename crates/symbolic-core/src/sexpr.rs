//! S-expression reader for PDDL with source positions and comments.
//! PDDL is case-insensitive: all atoms are lowercased at lex time.

use crate::error::{FlickerError, FlickerResult, Pos};

#[derive(Debug, Clone, PartialEq)]
pub enum Sexp {
    Atom(String, Pos),
    List(Vec<Sexp>, Pos),
}

impl Sexp {
    pub fn pos(&self) -> &Pos {
        match self {
            Sexp::Atom(_, p) | Sexp::List(_, p) => p,
        }
    }

    pub fn atom_str(&self) -> Option<&str> {
        match self {
            Sexp::Atom(s, _) => Some(s),
            Sexp::List(_, _) => None,
        }
    }

    pub fn is_atom(&self, name: &str) -> bool {
        matches!(self, Sexp::Atom(s, _) if s == name)
    }

    pub fn list_items(&self) -> Option<&[Sexp]> {
        match self {
            Sexp::List(v, _) => Some(v),
            Sexp::Atom(_, _) => None,
        }
    }

    /// First element of a list (usually the head keyword/operator).
    pub fn head(&self) -> Option<&Sexp> {
        self.list_items().and_then(|v| v.first())
    }
}

struct Lexer<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    line: usize,
    col: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self { src, bytes: src.as_bytes(), pos: 0, line: 1, col: 1 }
    }

    fn advance(&mut self) {
        if let Some(&b) = self.bytes.get(self.pos) {
            if b == b'\n' {
                self.line += 1;
                self.col = 1;
            } else {
                self.col += 1;
            }
            self.pos += 1;
        }
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            match self.bytes.get(self.pos) {
                Some(b';') => {
                    while let Some(&b) = self.bytes.get(self.pos) {
                        if b == b'\n' {
                            break;
                        }
                        self.advance();
                    }
                }
                Some(b) if b.is_ascii_whitespace() => self.advance(),
                _ => break,
            }
        }
    }

    fn read_atom(&mut self) -> String {
        let start = self.pos;
        while let Some(&b) = self.bytes.get(self.pos) {
            if b == b'(' || b == b')' || b.is_ascii_whitespace() || b == b';' {
                break;
            }
            self.advance();
        }
        self.src[start..self.pos].to_lowercase()
    }
}

pub fn parse_sexps(src: &str) -> FlickerResult<Vec<Sexp>> {
    let mut lx = Lexer::new(src);
    let mut out = Vec::new();
    loop {
        lx.skip_ws_and_comments();
        if lx.pos >= lx.bytes.len() {
            break;
        }
        out.push(parse_one(&mut lx)?);
    }
    Ok(out)
}

fn parse_one(lx: &mut Lexer<'_>) -> FlickerResult<Sexp> {
    lx.skip_ws_and_comments();
    let pos = Pos { line: lx.line, col: lx.col };
    match lx.bytes.get(lx.pos) {
        None => Err(FlickerError::at("parse", "unexpected end of input", pos)),
        Some(b'(') => {
            lx.advance();
            let mut items = Vec::new();
            loop {
                lx.skip_ws_and_comments();
                match lx.bytes.get(lx.pos) {
                    None => {
                        return Err(FlickerError::at("parse", "unterminated list", pos));
                    }
                    Some(b')') => {
                        lx.advance();
                        break;
                    }
                    Some(_) => items.push(parse_one(lx)?),
                }
            }
            Ok(Sexp::List(items, pos))
        }
        Some(b')') => Err(FlickerError::at("parse", "unexpected ')'", pos)),
        Some(_) => {
            let atom = lx.read_atom();
            if atom.is_empty() {
                return Err(FlickerError::at("parse", "empty atom", pos));
            }
            Ok(Sexp::Atom(atom, pos))
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_lists() {
        let s = parse_sexps("(a (b c) ; comment\n (d))").expect("ok");
        assert_eq!(s.len(), 1);
        let items = s[0].list_items().expect("list");
        assert_eq!(items.len(), 3);
        assert!(items[0].is_atom("a"));
    }

    #[test]
    fn lowercases_atoms() {
        let s = parse_sexps("(Move TRUCK1)").expect("ok");
        let items = s[0].list_items().expect("list");
        assert_eq!(items[0].atom_str(), Some("move"));
        assert_eq!(items[1].atom_str(), Some("truck1"));
    }

    #[test]
    fn unterminated_list_error() {
        let e = parse_sexps("(a (b").unwrap_err();
        assert_eq!(e.kind, "parse");
        assert!(e.pos.is_some());
    }

    #[test]
    fn positions_are_tracked() {
        let s = parse_sexps("(a\n  b)").expect("ok");
        let items = s[0].list_items().expect("list");
        assert_eq!(items[1].pos().line, 2);
        assert_eq!(items[1].pos().col, 3);
    }
}
