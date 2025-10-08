use base64::{Engine as _, engine::general_purpose};

pub fn parse_cmd(line: &str) -> (String, Option<&str>) {
    if let Some(idx) = line.find(' ') {
        return (
            line[..idx].to_ascii_uppercase(),
            Some(line[idx + 1..].trim()),
        );
    }

    (line.to_ascii_uppercase(), None)
}

pub fn parse_mail_from(line: &str) -> Option<(String, Option<String>)> {
    crate::constants::MAIL_FROM_RE.captures(line).map(|caps| {
        let email = caps.get(1).unwrap().as_str().to_string();
        let params = caps.get(2).map(|m| m.as_str().to_string());
        (email, params)
    })
}

pub fn parse_size(arg: &str) -> Option<usize> {
    crate::constants::MAIL_SIZE_RE
        .captures(arg)
        .and_then(|caps| caps.get(1))
        .and_then(|m| m.as_str().parse::<usize>().ok())
}

pub fn parse_rcpt_to(line: &str) -> Option<&str> {
    crate::constants::RCPT_TO_RE
        .captures(line)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str())
}

pub fn parse_b64_line(line: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD.decode(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cmd_correctly() {
        let cases = vec![
            ("starttls", "STARTTLS", ""),
            ("quite", "QUITE", ""),
            ("HELO remotename", "HELO", "remotename"),
            ("EHLo new name", "EHLO", "new name"),
            ("NOOP", "NOOP", ""),
            ("RSET", "RSET", ""),
            ("AUTH username", "AUTH", "username"),
            ("DATA", "DATA", ""),
            ("XCLIENT x_client_addr", "XCLIENT", "x_client_addr"),
            (
                "MAIL FROM:<hello@world.com>",
                "MAIL",
                "FROM:<hello@world.com>",
            ),
            ("RCPT TO:<rcpt@mail.com>", "RCPT", "TO:<rcpt@mail.com>"),
        ];

        for (line, e_cmd, e_arg) in cases {
            let (cmd, arg) = parse_cmd(line);

            assert_eq!(cmd, e_cmd, "failed for input: {}", line);
            assert_eq!(
                arg.as_deref(),
                if e_arg.is_empty() { None } else { Some(e_arg) },
                "failed for input: {}",
                line
            );
        }
    }

    #[test]
    fn parse_mail_from_correctly() {
        let cases = vec![
            ("FROM:<hello@world.com>", "hello@world.com", ""),
            ("FROM<ok@hey.com>", "", ""),
            ("<Hello@com.com>", "", ""),
            ("FROM:<ok@ok.io> SIZE:1024", "ok@ok.io", "SIZE:1024"),
        ];

        for (line, expect, param) in cases {
            let from = parse_mail_from(line);

            assert_eq!(
                from,
                if expect.is_empty() {
                    None
                } else {
                    Some((
                        expect.to_string(),
                        if param.is_empty() {
                            None
                        } else {
                            Some(param.to_string())
                        },
                    ))
                }
            );
        }
    }

    #[test]
    fn parse_size_correctly() {
        let cases = vec![
            ("SIZE=1234", Some(1234)),
            ("SIZE=...", None),
            ("size=444", Some(444)),
        ];

        for (line, expected) in cases {
            let res = parse_size(line);
            assert_eq!(res, expected);
        }
    }

    #[test]
    fn parse_rcpt_to_correctly() {
        let cases = vec![
            ("TO: <abc@example.com>", "abc@example.com"),
            ("TO:hello@world.co", ""),
            ("to:  <user@mail.com>", "user@mail.com"),
        ];

        for (line, excepted) in cases {
            let res = parse_rcpt_to(line);
            assert_eq!(
                res,
                if excepted.is_empty() {
                    None
                } else {
                    Some(excepted)
                }
            );
        }
    }
}
