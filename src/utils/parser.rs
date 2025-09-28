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
