# TrustLink 스토리지 확장 가이드 (온프레미스 → SaaS)

> 원칙: **코드 재작성이 아니라 "설정 전환 + 1회 마이그레이션"으로 진화**한다.
> zot은 스토리지 드라이버(local/S3/GCS)와 멀티테넌트(subPaths)를 네이티브로 지원하므로,
> 지금부터 아래 규칙만 지키면 단계별 확장이 설정 변경만으로 가능하다.

## 0. 지금부터 지킬 3가지 규칙 (확장 대비)
1. **테넌트 = repo 네임스페이스 prefix** (`innotium/**`, 추후 `<tenant>/**`). accessControl도 이 단위로 작성.
2. **데이터는 전용 경로/볼륨**에만 둔다 (호스트 OS 볼륨과 분리 → 디스크 풀이 host를 죽이지 않게).
3. **dedupe/gc/retention은 항상 켠 채** 운영 (용량 증가 억제).

## 1단계 — 온프레미스 단일 노드 (현재)
```jsonc
"storage": {
  "rootDirectory": "/var/lib/registry",   // 전용 볼륨 마운트
  "dedupe": true, "gc": true,
  "gcDelay": "1h", "gcInterval": "24h",
  "retention": { "dryRun": false, "delay": "168h", "policies": [ /* 제품별 보존 */ ] }
}
```
- 용량 관리: 관리 콘솔 ▸ 용량(디스크 사용률·repo별), 임계 알림(85/95%), 리텐션 dryRun→실삭제.
- 한계: 단일 노드, 디스크 = 물리 볼륨 상한. → 2단계로.

## 2단계 — 전용 볼륨 확장 (수직 확장)
- LVM/클라우드 디스크로 볼륨 확장(무중단 가능). 설정 변경 없음.
- 여전히 단일 노드. HA·대용량·멀티테넌트 격리가 필요해지면 3단계.

## 3단계 — 오브젝트 스토리지 전환 (S3/MinIO)  ← SaaS 기반
```jsonc
"storage": {
  "rootDirectory": "/registry",
  "gc": true,
  "storageDriver": {
    "name": "s3", "region": "us-east-1",
    "regionendpoint": "http://minio:9000",   // 또는 AWS S3 엔드포인트
    "bucket": "trustlink", "rootdirectory": "/registry",
    "accesskey": "…", "secretkey": "…", "secure": false
  },
  "cacheDriver": { "name": "redis", "url": "redis://redis:6379", "keyprefix": "zot" }
}
```
> 관리 콘솔 ▸ **설정·스토리지** 에서 이 블록을 폼으로 생성할 수 있다(`/api/storage/preview`).

**전환 절차(1회):**
1. 오브젝트 스토리지(MinIO 컨테이너 또는 클라우드 S3) + 버킷 생성, 자격증명 준비.
2. zot 중지 → 로컬 데이터 → 버킷으로 마이그레이션 (`mc mirror` 또는 `rclone copy /var/lib/registry s3:trustlink/registry`).
3. config의 `storage`를 위 S3 블록으로 교체(로컬 `rootDirectory`만 남기고 `storageDriver` 추가).
4. dedupe는 S3에서 하드링크 불가 → **off**, 중복제거는 cacheDriver(redis) + GC에 의존.
5. zot 재기동 → catalog/pull 검증.

- 효과: 스토리지가 사실상 **무한·탄력적**, 노드와 분리 → 다중 인스턴스 가능.

## 4단계 — 멀티테넌트 SaaS (수평 확장)
```jsonc
"storage": {
  "storageDriver": { "name": "s3", "bucket": "trustlink", ... },
  "cacheDriver":   { "name": "redis", "url": "redis://redis:6379" },
  "subPaths": {
    "/tenant-a": { "rootDirectory": "/tenant-a", "storageDriver": { "name": "s3", "bucket": "tl-tenant-a", ... } },
    "/tenant-b": { "rootDirectory": "/tenant-b", "storageDriver": { "name": "s3", "bucket": "tl-tenant-b", ... } }
  }
}
```
- **테넌트별 버킷/경로 격리**(subPaths), 테넌트별 리텐션 정책 분리 가능.
- 여러 zot 인스턴스 + 공유 **cacheDriver(redis)** + 앞단 LB → 수평 확장/HA.
- 인증: Keycloak realm 또는 group 으로 테넌트 분리, accessControl을 `<tenant>/**` 단위로.
- 쿼터(테넌트별 용량 상한): zot 미지원 → 관리 BFF/외부 어드미션에서 메트릭(`zot_repo_storage_bytes`) 기반 강제.

## 마이그레이션/롤백 메모
- 각 단계 전환 전 **dryRun/백업** 필수. S3 전환은 데이터 복제 후 컷오버(롤백=로컬 config 복귀).
- distSpec/OCI 레이아웃은 드라이버 무관 → 마이그레이션은 단순 바이트 복사.

## 단계 요약
| 단계 | 스토리지 | 확장축 | 전환 비용 |
|---|---|---|---|
| 1 현재 | local + 전용볼륨 | - | - |
| 2 | local 볼륨 확장 | 수직 | 무중단 |
| 3 | S3/MinIO | 노드분리 | config + 1회 마이그레이션 |
| 4 SaaS | S3 + subPaths + redis | 수평/멀티테넌트 | config(테넌트 추가) |
