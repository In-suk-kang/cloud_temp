> AWS 인프라(IAM, Security Group, EC2, S3, VPC, CloudTrail)의 현재 보안 및 리소스 상태를 수집하여 JSON 스냅샷으로 저장하는 자동화 도구입니다. 취약점 점검, 인프라 변경 전후(`before`/`after`) 비교, 보안 감사(Audit) 등의 목적에 활용할 수 있습니다.

---

## 🛠 주요 기능 (Features)

* **멀티 서비스 지원:** 총 6가지 핵심 AWS 서비스 및 리소스 수집
    * **IAM:** 사용자(Users), 그룹(Groups), 역할(Roles) 및 연결된/인라인 정책 정보
    * **Security Group:** 인바운드/아웃바운드 규칙, 프로토콜, 포트, CIDR 범위
    * **EC2:** 인스턴스 상태, 네트워크 인터페이스(ENI), 볼륨(EBS), 태그 정보
    * **S3:** 버킷 리전, 퍼블릭 액세스 차단 설정, 버킷 정책, ACL, 암호화 상태
    * **VPC:** VPC, 서브넷, 라우트 테이블, 인터넷 게이트웨이, 네트워크 ACL(NACL)
    * **CloudTrail:** 추적(Trail) 로깅 활성화 상태, 이벤트 셀렉터 설정
* **안전한 예외 처리:** 권한 부족이나 API 호출 실패 시 `ClientError`를 안전하게 핸들링(`safe_call`)하여 전체 수집 프로세스가 중단되지 않도록 설계
* **비교 분석 최적화:** `before`와 `after` 인자를 통해 인프라 변경 작업 전후의 스냅샷을 체계적으로 분리 저장

---

## 📂 프로젝트 구조 (Directory Structure)

```text
.
├── snapshot.py          # 메인 수집 스크립트
└── snapshots/           # 스냅샷 저장 디렉토리 (자동 생성)
    ├── before/          # 변경 작업 전 스냅샷
    │   ├── snapshot_YYYYMMDD_HHMMSS.json
    │   ├── iam.json
    │   ├── security_group.json
    │   ├── ec2.json
    │   ├── s3.json
    │   ├── vpc.json
    │   └── cloudtrail.json
    └── after/           # 변경 작업 후 스냅샷
        └── ...
