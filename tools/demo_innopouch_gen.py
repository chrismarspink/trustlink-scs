#!/usr/bin/env python3
"""innoPouch 시연 데이터 생성 — 버전 1.0~N.0 의 바이너리(tar.gz)·CycloneDX SBOM·설치 매뉴얼(md).

버전이 올라갈수록 알려진 취약 라이브러리를 수정 버전으로 올리고 구성요소를 늘려,
TrustLink 대시보드에서 "구성요소 증가 · 취약점 감소" 추이가 보이게 한다.
사용: python3 demo_innopouch_gen.py <출력 폴더> [버전 수=10]
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
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": "2026-10-27T00:00:00Z",
            "tools": [{"vendor": "Innotium", "name": "XScan (demo)", "version": "1.0"}],
            "component": {"type": "application", "bom-ref": f"pkg:generic/innotium/innopouch@{ver}",
                          "name": "innoPouch", "version": ver, "publisher": "Innotium",
                          "description": "TrustLink 시연용 가상 제품(알려진 취약 OSS 를 버전별로 수정)"},
        },
        "components": comps,
    }


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


def binary(n: int) -> bytes:
    ver = f"{n}.0"
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


def main():
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
