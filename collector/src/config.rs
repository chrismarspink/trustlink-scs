//! 외부 사이드카 설정 — 바이너리에 토큰/설정을 넣지 않음(서명 유지).
//! 실행파일 옆의 `ismart-collector.conf` (key=value) 를 읽습니다.
//!   issue_id=TL-2026-0042
//!   upload_token=<1회용>
//!   endpoint=https://trustlink.innotium.com/api/collector
//!   offline=false
//!   scope=product            # product(기본) | system
//!   profile=ismart-platform  # 제품 프로파일 이름
//!   collect=os_info,security_software,process_modules,product_logs,crash_dumps  # 생략=전체
//!
//! 설정 우선순위: 명령행 플래그 > 사이드카 conf > 기본값.
//! (관리자가 TrustLink에서 이슈 발급 시 conf에 값을 심어 전달 → 사용자는 신경 쓰지 않음)

use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// 제품 프로파일에 매칭되는 경로·프로세스·로그만(기본, 최소 수집).
    Product,
    /// 시스템 전역(설치 보안SW 전체·전체 프로세스 등). 추가 동의 대상.
    System,
}

impl Scope {
    pub fn parse(s: &str) -> Option<Scope> {
        match s.trim().to_ascii_lowercase().as_str() {
            "product" => Some(Scope::Product),
            "system" => Some(Scope::System),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Scope::Product => "제품 한정",
            Scope::System => "시스템 전역",
        }
    }
}

pub struct Config {
    pub issue_id: Option<String>,
    pub upload_token: Option<String>,
    pub endpoint: Option<String>,
    pub offline: bool,
    pub scope: Scope,
    pub profile: String,
    /// None = 전체 카테고리 수집.
    pub categories: Option<Vec<String>>,
    /// 모듈을 반드시 수집할 프로세스 이름들(예: Code.exe). 범위와 무관.
    pub targets: Vec<String>,
}

impl Config {
    pub fn load_sidecar() -> Config {
        let text = std::fs::read_to_string(sidecar_path()).unwrap_or_default();
        let kv = parse_kv(&text);
        Config {
            issue_id: kv.get("issue_id").cloned(),
            upload_token: kv.get("upload_token").cloned(),
            endpoint: kv.get("endpoint").cloned(),
            offline: kv.get("offline").map(|v| v == "true").unwrap_or(false),
            scope: kv.get("scope").and_then(|s| Scope::parse(s)).unwrap_or(Scope::Product),
            profile: kv.get("profile").cloned().unwrap_or_else(|| "ismart-platform".to_string()),
            categories: kv.get("collect").map(|v| {
                v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
            }),
            targets: kv
                .get("targets")
                .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_default(),
        }
    }

    /// 카테고리가 수집 대상인지(None=전체).
    pub fn wants(&self, name: &str) -> bool {
        match &self.categories {
            None => true,
            Some(list) => list.iter().any(|c| c == name),
        }
    }
}

fn sidecar_path() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap_or_default();
    p.set_file_name("ismart-collector.conf");
    p
}

fn parse_kv(text: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            m.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    m
}
