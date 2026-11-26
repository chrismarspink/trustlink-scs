//! 이노스마트 진단 수집기 (ismart-collector) — 1차 포터블
//!
//! 실행 모델(조사 결과 반영: Velociraptor "단일 바이너리 2모드" 패턴)
//!   - 인자 없음(더블클릭) = 1회 수집 → 번들 생성 → (업로드) → 종료   [1차]
//!   - --install                = per-user 예약작업으로 상주 등록           [2차, 골격만]
//!
//! 설정·토큰은 바이너리에 넣지 않고 외부 사이드카 파일에서 읽습니다
//! (서명 유지 — 설정을 바이너리에 재패킹하면 Authenticode 서명이 깨짐).

mod bundle;
mod collect;
mod config;
mod redact;

use config::Scope;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if has_flag(&args, "--version") || has_flag(&args, "-V") {
        println!("ismart-collector {VERSION}");
        return ExitCode::SUCCESS;
    }
    if has_flag(&args, "--help") || has_flag(&args, "-h") {
        print_help();
        return ExitCode::SUCCESS;
    }
    if has_flag(&args, "--install") {
        eprintln!("[2차 예정] 상주(per-user 예약작업) 설치는 다음 단계에서 활성화됩니다.");
        return ExitCode::SUCCESS;
    }
    run_portable(&args)
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// `--scope product|system` 값을 읽습니다(있으면 conf 를 덮어씀).
fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let i = args.iter().position(|a| a == flag)?;
    args.get(i + 1).map(String::as_str)
}

fn print_help() {
    println!(
        "이노스마트 진단 수집기 {VERSION}\n\
         사용법:\n\
         \tismart-collector                     더블클릭/무인자 — 1회 진단 수집\n\
         \tismart-collector --scope system      수집 범위 지정(product|system)\n\
         \tismart-collector --install           상주 등록(2차)\n\
         \tismart-collector --version           버전 출력\n\
         \tismart-collector --help              도움말\n\
         설정 우선순위: 플래그 > ismart-collector.conf > 기본값(product)"
    );
}

/// 1차 포터블: 동의 → 수집 → 마스킹 → 번들 → (업로드 스텁)
fn run_portable(args: &[String]) -> ExitCode {
    let mut cfg = config::Config::load_sidecar();

    // 명령행 --scope 가 conf 를 덮어씀.
    if let Some(v) = flag_value(args, "--scope") {
        match Scope::parse(v) {
            Some(s) => cfg.scope = s,
            None => {
                eprintln!("알 수 없는 --scope 값: {v} (product|system)");
                return ExitCode::FAILURE;
            }
        }
    }

    println!("이노스마트 진단 수집기 {VERSION}");
    println!("이슈 번호: {}", cfg.issue_id.as_deref().unwrap_or("(없음)"));
    println!("수집 범위: {} · 프로파일: {}", cfg.scope.label(), cfg.profile);
    println!("수집을 시작합니다. 민감정보는 수집 즉시 가려집니다.\n");

    let mut items = collect::run_all(&cfg);
    for it in &mut items {
        it.data = redact::mask(&it.data);
    }

    match bundle::write_bundle(&cfg, &items) {
        Ok(path) => {
            println!("\n번들 생성 완료: {}", path);
            println!("다음 단계(업로드/오프라인 전달)는 전달 설계에 따라 연결됩니다.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("번들 생성 실패: {e}");
            ExitCode::FAILURE
        }
    }
}
