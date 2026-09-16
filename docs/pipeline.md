# AWS Infrastructure Security Snapshot & Analysis Pipeline (`pipeline.md`)

이 문서는 AWS 인프라 보안 스냅샷 수집부터 변경점(Diff) 추출, 데이터 정규화, Cypher 쿼리 변환 및 Neo4j 그래프 데이터베이스 적재까지 연결되는 **전체 데이터 파이프라인**을 설명합니다 [3, 4, 5].

---

## 1. 전체 파이프라인 개요 (Pipeline Overview)

파이프라인은 크게 **4단계(수집 → 비교 → 정규화 → 적재)**로 구성되어 있으며 [3, 4, 5], 각 스크립트는 모듈화되어 독립적으로 실행되거나 연계 파이프라인으로 작동합니다.

```
[1단계: 수집]          [2단계: 비교]            [3단계: 정규화]               [4단계: 적재]
snapshot.py   ───►     diff.py      ───►    normalize_diff.py  ───►    diff_to_cypher.py & neo4j_loader.py
(before/after)     (snapshots diff)          (graph formatting)            (Neo4j Graph DB)
```

---

## 2. 단계별 상세 설명 (Pipeline Stages)

### 2.1 [1단계] 스냅샷 수집 (`snapshot.py`)
* **역할**: Boto3 SDK를 활용하여 6개 AWS 핵심 서비스(IAM, SG, EC2, S3, VPC, CloudTrail)의 보안 상태 메타데이터를 수집합니다 [4].
* **실행 모드**: `before` 및 `after` 인자를 받아 인프라 변경 작업 전후 상태를 개별 디렉터리에 저장합니다 [4, 5].
* **출력 결과**: `snapshots/before/*.json`, `snapshots/after/*.json` [5]

### 2.2 [2단계] 변경점 추출 (`diff.py`)
* **역할**: `snapshots/before/`와 `snapshots/after/` 디렉터리 내의 서비스별 JSON 스냅샷들을 비교합니다 [3, 5].
* **처리 내용**: 리소스의 신규 생성(Added), 삭제(Removed), 설정 변경(Modified) 내역을 탐지하여 델타(Delta) 데이터를 추출합니다 [4, 5].
* **출력 결과**: `diff.json` (변경 사항 추출 데이터)

### 2.3 [3단계] 데이터 정규화 (`normalize_diff.py`)
* **역할**: `diff.py`에서 생성된 원시 변경 내역 데이터를 그래프 데이터베이스 스키마에 맞게 정규화합니다 [3].
* **처리 내용**:
  * AWS 리소스 간 관계(Relationship) 연결을 위한 노드(Node) 및 엣지(Edge) 스키마 정의
  * 리소스 ARN/ID 기반 식별자 통일 및 프로퍼티 구조 단순화

### 2.4 [4단계] Cypher 쿼리 변환 및 DB 적재 (`diff_to_cypher.py` & `neo4j_loader.py`)
* **Cypher 변환 (`diff_to_cypher.py`)**: 정규화된 diff 데이터를 Neo4j에서 해석 가능한 Cypher `CREATE`, `MATCH`, `MERGE` 문으로 변환합니다 [3].
* **DB 적재 (`neo4j_loader.py`)**: 변환된 Cypher 쿼리를 실행하여 Neo4j Graph DB에 그래프 구조로 적재합니다 [3].
* **최종 활용**: Neo4j Browser 또는 Bloom을 통해 인프라 변경에 따른 보안 영향도 및 리소스 연관 관계를 시각적으로 분석합니다 [3, 4].

---

## 3. 파이프라인 실행 방법 (Execution Guide)

```bash
# 1. 변경 작업 전 스냅샷 수집
python snapshot.py before

# 2. (인프라 변경 또는 공격 시뮬레이션 수행)

# 3. 변경 작업 후 스냅샷 수집
python snapshot.py after

# 4. 전후 변경점(Diff) 추출
python diff.py

# 5. Diff 데이터 정규화
python normalize_diff.py

# 6. Cypher 변환 및 Neo4j 적재
python diff_to_cypher.py
python neo4j_loader.py
```

---
*문서 작성 기준: AWS Infrastructure Security Snapshot and Analysis Tool (`cloud_temp`)*
