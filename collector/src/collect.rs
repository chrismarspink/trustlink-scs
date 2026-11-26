//! 수집기 — 코어가 수집을 수행.
//!
//! v0.1.0: Windows 내장 명령(tasklist/reg/powershell CIM) + 표준 파일 접근으로 기능 구현.
//!         (이 코드는 모든 플랫폼에서 컴파일되며, 실제 명령은 Windows 에서만 실행된다.)
//! v0.2.0: windows-rs 네이티브 API로 경화(속도·견고성).

use crate::config::{Config, Scope};

pub struct CollectItem {
    pub name: String,
    pub data: String,
}

impl CollectItem {
    fn new(name: &str, data: impl Into<String>) -> CollectItem {
        CollectItem { name: name.to_string(), data: data.into() }
    }
}

/// 수집 항목(1차). 범위(scope)와 카테고리 설정을 반영.
pub fn run_all(cfg: &Config) -> Vec<CollectItem> {
    let steps: &[(&str, fn(&Config) -> String)] = &[
        ("os_info", os_info),
        ("security_software", security_software),
        ("process_modules", process_modules),
        ("product_logs", product_logs),
        ("crash_dumps", crash_dumps),
    ];
    steps
        .iter()
        .filter(|(name, _)| cfg.wants(name))
        .map(|(name, f)| {
            println!("  · 수집: {name} [{}]", cfg.scope.label());
            CollectItem::new(name, f(cfg))
        })
        .collect()
}

// ── 수집 구현 ──────────────────────────────────────────────

fn os_info(_cfg: &Config) -> String {
    if !cfg!(windows) {
        return stub();
    }
    let ver = run("cmd", &["/c", "ver"]);
    let reg = run(
        "reg",
        &["query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"],
    );
    format!("{ver}\n{reg}")
}

/// 설치 보안SW + 등록된 백신(SecurityCenter2). product 범위는 프로파일 키워드로 좁힌다.
fn security_software(cfg: &Config) -> String {
    if !cfg!(windows) {
        return stub();
    }
    let av = run(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | \
             Select-Object displayName,pathToSignedProductExe | Format-List",
        ],
    );
    // 설치 소프트웨어(언인스톨 키) — product 면 프로파일 키워드만, system 이면 전체(상한).
    let uninstall = run(
        "reg",
        &["query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "/s", "/v", "DisplayName"],
    );
    let sw = match cfg.scope {
        Scope::Product => filter_lines(&uninstall, &profile_keywords(&cfg.profile)),
        Scope::System => cap(&uninstall, 8000),
    };
    format!("[등록 백신]\n{av}\n\n[설치 소프트웨어]\n{sw}")
}

/// 프로세스별 로드 모듈. product 범위는 제품 프로세스만 → 주입된 후킹 DLL 노출.
fn process_modules(cfg: &Config) -> String {
    if !cfg!(windows) {
        return stub();
    }
    let out = run("tasklist", &["/m", "/fo", "csv"]);
    match cfg.scope {
        Scope::Product => filter_lines(&out, &profile_keywords(&cfg.profile)),
        Scope::System => cap(&out, 12000),
    }
}

/// 제품 로그 경로 탐색(프로파일 기준). 파일 목록만, 내용은 뒤 단계에서 선별.
fn product_logs(cfg: &Config) -> String {
    if !cfg!(windows) {
        return stub();
    }
    let mut dirs = Vec::new();
    for base in ["ProgramData", "LOCALAPPDATA"] {
        if let Ok(v) = std::env::var(base) {
            dirs.push(format!("{v}\\{}", cfg.profile));
        }
    }
    list_dirs(&dirs)
}

/// 크래시 덤프 경로(WER/CrashDumps) 목록.
fn crash_dumps(_cfg: &Config) -> String {
    if !cfg!(windows) {
        return stub();
    }
    let mut dirs = Vec::new();
    if let Ok(la) = std::env::var("LOCALAPPDATA") {
        dirs.push(format!("{la}\\CrashDumps"));
    }
    if let Ok(pd) = std::env::var("ProgramData") {
        dirs.push(format!("{pd}\\Microsoft\\Windows\\WER\\ReportQueue"));
    }
    list_dirs(&dirs)
}

// ── 헬퍼 ──────────────────────────────────────────────────

fn stub() -> String {
    "(비-Windows 호스트 — 스텁. 이 도구는 Windows 전용입니다.)".into()
}

/// 외부 명령 실행 → stdout(비면 stderr) 트림. 실패해도 패닉하지 않음.
fn run(program: &str, args: &[&str]) -> String {
    match std::process::Command::new(program).args(args).output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            if s.trim().is_empty() {
                s = String::from_utf8_lossy(&o.stderr).into_owned();
            }
            cap(s.trim(), 16000)
        }
        Err(e) => format!("(실행 실패: {program}: {e})"),
    }
}

fn profile_keywords(profile: &str) -> Vec<String> {
    // NOTE: 실제 제품 프로세스/설치명으로 교체 필요(또는 서명 룰 팩에서 주입).
    match profile {
        "ismart-platform" => vec!["ismart".into(), "innosmart".into()],
        other => vec![other.to_string()],
    }
}

/// 키워드(대소문자 무시)가 든 줄만 남긴다.
fn filter_lines(text: &str, keywords: &[String]) -> String {
    let kw: Vec<String> = keywords.iter().map(|k| k.to_ascii_lowercase()).collect();
    let picked: Vec<&str> = text
        .lines()
        .filter(|line| {
            let l = line.to_ascii_lowercase();
            kw.iter().any(|k| l.contains(k.as_str()))
        })
        .collect();
    if picked.is_empty() {
        "(제품 프로파일 매칭 항목 없음)".into()
    } else {
        cap(&picked.join("\n"), 12000)
    }
}

/// 디렉터리 목록(파일명·크기). 경로가 없으면 표기.
fn list_dirs(dirs: &[String]) -> String {
    let mut out = String::new();
    for d in dirs {
        out.push_str(&format!("[{d}]\n"));
        match std::fs::read_dir(d) {
            Ok(rd) => {
                let mut n = 0;
                for e in rd.flatten() {
                    let len = e.metadata().map(|m| m.len()).unwrap_or(0);
                    out.push_str(&format!("  {} ({} bytes)\n", e.file_name().to_string_lossy(), len));
                    n += 1;
                    if n >= 200 {
                        out.push_str("  … (생략)\n");
                        break;
                    }
                }
                if n == 0 {
                    out.push_str("  (비어 있음)\n");
                }
            }
            Err(_) => out.push_str("  (없음/접근 불가)\n"),
        }
    }
    out
}

/// 길이 상한(번들 비대 방지).
fn cap(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push_str("\n… (상한 초과로 생략)");
        t
    }
}
