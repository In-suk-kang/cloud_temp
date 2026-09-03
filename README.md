# Cloud Drift Forensics & Attack Path Reconstruction

> **Log-Agnostic Post-Compromise Graph Attribution Framework in AWS**

공격자가 `CloudTrail` 등 감사 로깅을 무력화(`Defense Evasion`)한 블라인드 스팟(Blind Spot) 환경에서, 로깅 공백 전후의 **인프라 상태 변화(State Drift)**를 추출하고 이를 **Neo4j 그래프 데이터베이스**로 적재하여 공격자의 횡적 이동 및 침해 경로를 역추적하는 보안 프레임워크입니다.

---

## 🚀 Key Features (핵심 특징)

1. **Anti-Forensics Resiliency (로그 의존성 탈피):** 
   * 공격자가 감사 로그를 중단하거나 삭제해도, AWS 리소스에 남은 최종 형상 변조 결과(State Drift)를 통해 침해 사고를 사후 복원합니다.
2. **Multi-Service State Snapshot (범용 형상 수집):** 
   * `CloudTrail`, `EC2`, `S3`, `IAM`, `KMS`, `Secrets Manager` 등 핵심 인프라 자원의 메타데이터와 세부 정책(백도어, 권한 변조 등)을 정밀 캡처합니다.
3. **Graph-based Attack Reconstruction (그래프 기반 인과관계 추론):** 
   * 수집된 Drift 데이터를 Neo4j에 적재하고, 방어 회피 전술과 임팩트 전술 간의 논리적 선후 관계(`PRECEDES`)를 자동으로 엮어 다단계 킬 체인(Kill Chain)을 시각화합니다.

---

## 📂 Project Structure (디렉토리 구조)

```text
cloud-drift-forensics/
├── data/                      # 스냅샷 및 Drift 분석 결과 JSON (Gitignore 대상)
│   ├── snapshot_before.json
│   ├── snapshot_after.json
│   └── drift_result.json
├── src/
│   ├── __init__.py
│   ├── detector.py            # AWS 상태 수집 및 델타 비교 엔진
│   └── ingestor.py            # Neo4j 그래프 적재 및 인과관계 매핑 모듈
├── main.py                    # 전체 파이프라인 실행 진입점
├── requirements.txt           # 필수 패키지 목록
└── README.md
