#!/usr/bin/env python3
"""innoPouch 시연 데이터 생성 — 버전 1.0~N.0 의 바이너리(tar.gz)·CycloneDX SBOM·설치 매뉴얼(md).

버전이 올라갈수록 알려진 취약 라이브러리를 수정 버전으로 올리고 구성요소를 늘려,
TrustLink 대시보드에서 "구성요소 증가 · 취약점 감소" 추이가 보이게 한다.
사용: python3 demo_innopouch_gen.py <출력 폴더> [버전 수=10]

웹 스택 시연(docs/DEMO-INNOPOUCH-WEB.md): 11.0 은 취약한 nginx·PHP·Node.js, 11.1 은 수정 버전.
사용: python3 demo_innopouch_gen.py <출력 폴더> --web [11.0|11.1 …]   (생략하면 둘 다)
1.0~10.0 의 데이터는 바뀌지 않는다(--web 은 별도 경로).
"""
import io
import json
import sys
import tarfile
import uuid
from pathlib import Path

# (이름, purl 형식, cpe 형식, 버전별 값: 처음 버전 → 이후 업그레이드 지점)
LIBS = [
    ("log4j-core", "pkg:maven/org.apache.logging.log4j/log4j-core@{v}", "cpe:2.3:a:apache:log4j:{v}:*:*:*:*:*:*:*",
     {1: "2.14.1", 3: "2.15.0", 4: "2.17.1", 10: "2.23.1"}),
    ("jackson-databind", "pkg:maven/com.fasterxml.jackson.core/jackson-databind@{v}", "cpe:2.3:a:fasterxml:jackson-databind:{v}:*:*:*:*:*:*:*",
     {1: "2.9.8", 5: "2.13.4", 9: "2.15.2"}),
    ("commons-collections", "pkg:maven/commons-collections/commons-collections@{v}", "cpe:2.3:a:apache:commons_collections:{v}:*:*:*:*:*:*:*",
     {1: "3.2.1", 6: "3.2.2"}),
    ("spring-core", "pkg:maven/org.springframework/spring-core@{v}", "cpe:2.3:a:vmware:spring_framework:{v}:*:*:*:*:*:*:*",
     {1: "5.3.17", 8: "5.3.30"}),
    ("lodash", "pkg:npm/lodash@{v}", "cpe:2.3:a:lodash:lodash:{v}:*:*:*:*:node.js:*:*",
     {1: "4.17.15", 4: "4.17.21"}),
    ("minimist", "pkg:npm/minimist@{v}", "cpe:2.3:a:minimist_project:minimist:{v}:*:*:*:*:node.js:*:*",
     {1: "1.2.0", 5: "1.2.8"}),
    ("django", "pkg:pypi/django@{v}", "cpe:2.3:a:djangoproject:django:{v}:*:*:*:*:*:*:*",
     {1: "2.2.0", 6: "3.2.18", 9: "4.2.11"}),
    ("requests", "pkg:pypi/requests@{v}", "cpe:2.3:a:python:requests:{v}:*:*:*:*:*:*:*",
     {1: "2.19.0", 8: "2.31.0"}),
    ("openssl", "pkg:generic/openssl@{v}", "cpe:2.3:a:openssl:openssl:{v}:*:*:*:*:*:*:*",
     {1: "1.1.1k", 7: "1.1.1w", 10: "3.0.13"}),
    ("zlib", "pkg:generic/zlib@{v}", "cpe:2.3:a:zlib:zlib:{v}:*:*:*:*:*:*:*",
     {1: "1.2.11", 7: "1.2.13"}),
]
# 웹 관리 콘솔 번들(11.x) — Dependency-Track 이 NVD CPE 로 매칭한다(pkg:generic 은 OSV·GitHub 대상이 아님).
# CPE 제품명은 NVD 가 실제로 쓰는 것: nginx 는 2025년 이후 CVE 가 f5:nginx_open_source 로 등록된다.
# 버전 근거(2026-11-20 확인): nginx.org 보안 권고·NVD, php.net ChangeLog-8·NVD·CISA KEV, nodejs.org 보안 릴리스·NVD.
WEB_STACK = [
    # (이름, purl, cpe, {11.0 취약 버전, 11.1 수정 버전})
    ("nginx", "pkg:generic/nginx@{v}", "cpe:2.3:a:f5:nginx_open_source:{v}:*:*:*:*:*:*:*",
     {"11.0": "1.28.0", "11.1": "1.30.7", "12.0": "1.30.6"}),  # 1.30.7 = 2026-11-18 stable(CVE-2026-123007 등 수정). 12.0 은 그 전날 출시 → 1.30.6
    ("php", "pkg:generic/php@{v}", "cpe:2.3:a:php:php:{v}:*:*:*:*:*:*:*",
     {"11.0": "8.3.7", "11.1": "8.3.37", "12.0": "8.3.37"}),     # 8.3.7: CVE-2024-4577·CVE-2026-109618/109619(KEV) 영향, 8.3.37 = 2026-11-19
    ("node", "pkg:generic/node@{v}", "cpe:2.3:a:nodejs:node.js:{v}:*:*:*:*:*:*:*",
     {"11.0": "22.12.0", "11.1": "22.23.5", "12.0": "22.23.5"}),  # 22.12.0: CVE-2026-111497(KEV, Brotli) 등, 22.23.5 = 2026-11-11 보안 릴리스
]
WEB_VERSIONS = ["11.0", "11.1", "12.0"]  # 12.0: 자동 대응 시연(패치 없음 → 개발자 통보)

# 버전마다 늘어나는 자체 모듈(취약점 없음) — 구성요소 수 추이용
INTERNAL = ["core", "agent", "policy", "crypto", "ui", "updater", "report", "sync", "audit", "plugin"]


def lib_version(points: dict, n: int) -> str:
    return points[max(k for k in points if k <= n)]


def sbom(n: int) -> dict:
    ver = f"{n}.0"
    comps = []
    for name, purl, cpe, points in LIBS:
        v = lib_version(points, n)
        p = purl.format(v=v)
        comps.append({"type": "library", "bom-ref": p, "name": name, "version": v, "purl": p, "cpe": cpe.format(v=v)})
    for i in range(3 * n + 2):
        mod = f"{INTERNAL[i % len(INTERNAL)]}-{i // len(INTERNAL) + 1}"
        p = f"pkg:generic/innotium/innopouch-{mod}@{ver}"
        comps.append({"type": "library", "bom-ref": p, "name": f"innopouch-{mod}", "version": ver, "purl": p,
                      "supplier": {"name": "Innotium"}})
    return bom_doc(ver, comps, "2026-10-27T00:00:00Z", "TrustLink 시연용 가상 제품(알려진 취약 OSS 를 버전별로 수정)")


def bom_doc(ver: str, comps: list, timestamp: str, desc: str) -> dict:
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "Innotium", "name": "XScan (demo)", "version": "1.0"}],
            "component": {"type": "application", "bom-ref": f"pkg:generic/innotium/innopouch@{ver}",
                          "name": "innoPouch", "version": ver, "publisher": "Innotium",
                          "description": desc},
        },
        "components": comps,
    }


def web_components(ver: str) -> list:
    """11.x 구성요소: 웹 콘솔 번들(nginx·PHP·Node.js) + 자체 모듈. 데모 초점을 흐리지 않게 1~10.0 의 OSS 라이브러리는 넣지 않는다."""
    comps = []
    for name, purl, cpe, vers in WEB_STACK:
        v = vers[ver]
        p = purl.format(v=v)
        comps.append({"type": "application", "bom-ref": p, "name": name, "version": v, "purl": p, "cpe": cpe.format(v=v)})
    for mod in INTERNAL + ["webconsole"]:
        p = f"pkg:generic/innotium/innopouch-{mod}@{ver}"
        comps.append({"type": "library", "bom-ref": p, "name": f"innopouch-{mod}", "version": ver, "purl": p,
                      "supplier": {"name": "Innotium"}})
    return comps


def web_sbom(ver: str) -> dict:
    ts = {"11.0": "2026-11-20T00:00:00Z", "11.1": "2026-11-20T01:00:00Z", "12.0": "2026-11-17T00:00:00Z"}[ver]
    desc = "TrustLink 시연용 가상 제품 — 웹 관리 콘솔(nginx·PHP·Node.js) " + {"11.0": "취약 버전 번들", "11.1": "보안 패치 번들", "12.0": "신규 메이저(nginx 1.30.6 — 2026-11-18 nginx 보안 릴리스 전날 출시)"}[ver]
    doc = bom_doc(ver, web_components(ver), ts, desc)
    doc["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'innopouch-web/' + ver)}"  # 다시 만들어도 같은 SBOM
    return doc


def web_guide(ver: str) -> str:
    rows = "\n".join(f"| {name} | {vers[ver]} |" for name, _, _, vers in WEB_STACK)
    if ver == "11.0":
        change = "- 웹 관리 콘솔 추가(nginx 리버스 프록시 + PHP-FPM 관리 화면 + Node.js 알림 서버)"
    elif ver == "12.0":
        change = "- 신규 메이저: 정책 엔진 개편, 웹 콘솔 nginx 1.30.6(출시 시점 최신 안정판)"
    else:
        prev = {name: vers["11.0"] for name, _, _, vers in WEB_STACK}
        change = "- 보안 패치: " + ", ".join(f"{name} {prev[name]} → {vers['11.1']}" for name, _, _, vers in WEB_STACK)
    return f"""# innoPouch {ver} 설치 가이드

## 1. 구성
- innopouch-{ver}-linux-amd64.tar.gz : 실행 파일·설정 예시
- SBOM(CycloneDX) : 구성요소 {len(web_components(ver))}개
- 이 문서

| 번들 구성요소 | 버전 |
|---|---|
{rows}

## 2. 설치
```bash
tar xzf innopouch-{ver}-linux-amd64.tar.gz
sudo ./innopouch/install.sh
innopouch --version   # {ver}
```

## 3. 이번 버전 변경
{change}

## 4. 문의
Innotium 기술지원 (TrustLink 시연용 가상 제품)
"""


def guide(n: int) -> str:
    ver = f"{n}.0"
    fixed = [name for name, _, _, pts in LIBS if n in pts and n > 1]
    return f"""# innoPouch {ver} 설치 가이드

## 1. 구성
- innopouch-{ver}-linux-amd64.tar.gz : 실행 파일·설정 예시
- SBOM(CycloneDX) : 구성요소 {len(LIBS) + 3 * n + 2}개
- 이 문서

## 2. 설치
```bash
tar xzf innopouch-{ver}-linux-amd64.tar.gz
sudo ./innopouch/install.sh
innopouch --version   # {ver}
```

## 3. 이번 버전 변경
- {"오픈소스 보안 업데이트: " + ", ".join(fixed) if fixed else "최초 공개 버전"}

## 4. 문의
Innotium 기술지원 (TrustLink 시연용 가상 제품)
"""


def binary(n) -> bytes:
    ver = n if isinstance(n, str) else f"{n}.0"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in {
            "innopouch/bin/innopouch": f"#!/bin/sh\necho 'innoPouch {ver} (TrustLink demo)'\n",
            "innopouch/install.sh": "#!/bin/sh\necho 'install innoPouch (demo)'\n",
            "innopouch/VERSION": ver + "\n",
        }.items():
            b = data.encode()
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode, ti.mtime = len(b), 0o755, 1761523200
            tf.addfile(ti, io.BytesIO(b))
    return buf.getvalue()


def write_web(out: Path, versions: list) -> None:
    for ver in versions:
        d = out / ver
        d.mkdir(parents=True, exist_ok=True)
        (d / f"innopouch-{ver}-linux-amd64.tar.gz").write_bytes(binary(ver))
        (d / f"innopouch-{ver}.cdx.json").write_text(json.dumps(web_sbom(ver), indent=2, ensure_ascii=False))
        (d / f"innopouch-{ver}-install-guide.md").write_text(web_guide(ver))
    print(f"웹 스택 버전 생성({', '.join(versions)}): {out}")


def main():
    if len(sys.argv) > 2 and sys.argv[2] == "--web":
        versions = sys.argv[3:] or WEB_VERSIONS
        bad = [v for v in versions if v not in WEB_VERSIONS]
        if bad:
            sys.exit(f"알 수 없는 웹 스택 버전: {bad} (가능: {WEB_VERSIONS})")
        write_web(Path(sys.argv[1]), versions)
        return
    out = Path(sys.argv[1])
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    for n in range(1, count + 1):
        d = out / f"{n}.0"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"innopouch-{n}.0-linux-amd64.tar.gz").write_bytes(binary(n))
        (d / f"innopouch-{n}.0.cdx.json").write_text(json.dumps(sbom(n), indent=2, ensure_ascii=False))
        (d / f"innopouch-{n}.0-install-guide.md").write_text(guide(n))
    print(f"{count}개 버전 생성: {out}")


if __name__ == "__main__":
    main()
