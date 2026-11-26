//! 마스킹 — 민감정보는 번들에 담기기 전에 가립니다(수집 즉시).
//! 1차는 표준 라이브러리만으로 보수적 치환. 2차에서 룰 기반 마스킹으로 확장.

/// 알려진 민감 패턴을 가립니다: 사용자 홈 경로, Bearer 토큰, key=value 형태의 비밀.
pub fn mask(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for line in input.lines() {
        out.push_str(&mask_line(line));
        out.push('\n');
    }
    out
}

fn mask_line(line: &str) -> String {
    let mut s = line.to_string();

    // C:\Users\<name>\...  →  C:\Users\***\...
    s = mask_user_path(&s);

    // 비밀로 보이는 key=value (password, token, secret, pwd, authorization)
    if let Some((k, _v)) = s.split_once('=') {
        let kl = k.trim().to_ascii_lowercase();
        if ["password", "passwd", "pwd", "token", "secret", "authorization", "apikey", "api_key"]
            .iter()
            .any(|needle| kl.contains(needle))
        {
            return format!("{k}=***");
        }
    }

    // Bearer <...>  →  Bearer ***
    if let Some(idx) = s.find("Bearer ") {
        let (head, _rest) = s.split_at(idx + "Bearer ".len());
        return format!("{head}***");
    }

    s
}

fn mask_user_path(s: &str) -> String {
    const MARK: &str = r"\Users\";
    let Some(pos) = s.find(MARK) else { return s.to_string() };
    let start = pos + MARK.len();
    let rest = &s[start..];
    let end = rest.find('\\').map(|e| start + e).unwrap_or(s.len());
    let mut out = String::new();
    out.push_str(&s[..start]);
    out.push_str("***");
    out.push_str(&s[end..]);
    out
}
