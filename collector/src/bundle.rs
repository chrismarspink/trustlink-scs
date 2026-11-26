//! 번들 생성 — 수집 항목 + 매니페스트를 출력 폴더에 씁니다.
//! 1차는 폴더로 생성(표준 라이브러리). 2차에서 `zip`·서명·업로드 연결.

use crate::collect::CollectItem;
use crate::config::Config;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn write_bundle(cfg: &Config, items: &[CollectItem]) -> std::io::Result<String> {
    let dir = out_dir(cfg);
    std::fs::create_dir_all(&dir)?;

    for it in items {
        let p = dir.join(format!("{}.txt", it.name));
        std::fs::write(p, it.data.as_bytes())?;
    }

    let manifest = build_manifest(cfg, items);
    std::fs::write(dir.join("manifest.json"), manifest.as_bytes())?;

    Ok(dir.to_string_lossy().into_owned())
}

fn out_dir(cfg: &Config) -> std::path::PathBuf {
    let issue = cfg.issue_id.clone().unwrap_or_else(|| "no-issue".to_string());
    let base = std::env::temp_dir();
    base.join(format!("ismart-diag-{}", sanitize(&issue)))
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

/// 매니페스트 — 1차는 손으로 만든 최소 JSON(의존성 0). 2차에서 serde_json 로 교체.
fn build_manifest(cfg: &Config, items: &[CollectItem]) -> String {
    let names: Vec<String> = items.iter().map(|i| format!("\"{}\"", i.name)).collect();
    format!(
        "{{\n  \"tool\": \"ismart-collector\",\n  \"version\": \"{}\",\n  \"issue_id\": \"{}\",\n  \"items\": [{}],\n  \"redacted\": true\n}}\n",
        VERSION,
        cfg.issue_id.as_deref().unwrap_or(""),
        names.join(", ")
    )
}
