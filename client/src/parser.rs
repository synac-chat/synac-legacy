pub fn parse(input: &str) -> Vec<String> {
    let mut parts  = Vec::new();
    let mut buffer = String::new();
    let mut escape = false;
    let mut quote  = false;

    for c in input.chars() {
        if escape {
            escape = false;
            if c != '\\' && c != '"' {
                buffer.push('\\');
            }
            buffer.push(c);
        } else {
            match c {
                '\\' => escape = true,
                '"' if buffer.is_empty() || quote => quote = !quote,
                ' ' if !quote => {
                    if !buffer.is_empty() {
                        parts.push(buffer);
                        buffer = String::new();
                    }
                },
                c => buffer.push(c)
            }
        }
    }

    if escape { buffer.push('\\'); }
    if !buffer.is_empty() { parts.push(buffer); }

    parts
}

#[cfg(test)]
#[test]
fn test() {
    assert_eq!(parse(r#"hello world"#), &["hello", "world"]);
    assert_eq!(parse(r#""hello world""#), &["hello world"]);
    assert_eq!(parse(r#"hel"lo wor"ld"#), &["hel\"lo", "wor\"ld"]);
    assert_eq!(parse(r#"hello\ world"#), &["hello\\ world"]);
    assert_eq!(parse(r#"\h\e\l\l\o world"#), &["\\h\\e\\l\\l\\o", "world"]);
    assert_eq!(parse(r#"\"hello world\""#), &["\"hello", "world\""]);
    assert_eq!(parse(r#"\\\"hello world\\\""#), &["\\\"hello", "world\\\""]);
}
