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
    // 레지스트리 제품키 항목(ProductId/DigitalProductId) 값 마스킹
    if let Some(m) = mask_reg_secret(line) {
        return m;
    }

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

/// `    ProductId    REG_SZ    00331-...` 같은 레지스트리 제품키 줄의 값을 가린다.
/// 이름(ProductId/DigitalProductId)과 REG 타입은 두고 값만 ***로.
fn mask_reg_secret(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let hit = ["DigitalProductId4", "DigitalProductId", "ProductId"]
        .iter()
        .any(|n| trimmed.starts_with(n));
    if !hit {
        return None;
    }
    if let Some(rpos) = line.find("REG_") {
        if let Some(sp) = line[rpos..].find(char::is_whitespace) {
            return Some(format!("{}    ***", &line[..rpos + sp]));
        }
    }
    Some(format!("{}    ***", line.trim_end()))
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
