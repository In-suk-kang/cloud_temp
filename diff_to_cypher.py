#!/usr/bin/env python3
"""
AWS State Diff JSON → Neo4j (Local Docker) 자동 적재
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
import json
from neo4j import GraphDatabase, basic_auth


class DiffToNeo4j:
    def __init__(
        self,
        diff_json: Dict[str, Any],
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "password",          # ← Docker에서 설정한 비밀번호로 변경
        database: str = "neo4j"
    ):
        self.diff = diff_json
        self.uri = uri
        self.user = user
        self.password = password
        self.database = database

        self.cypher_statements: List[str] = []
        self.attacker_account: Optional[str] = None
        self.victim_account = "746430304999"   # 필요시 수정

        self.driver = GraphDatabase.driver(
            self.uri,
            auth=basic_auth(self.user, self.password)
        )

    def close(self):
        self.driver.close()

    def generate_cypher(self) -> List[str]:
        """의미 있는 Diff만 Cypher로 변환"""
        self.cypher_statements = []
        self.cypher_statements.append("// ===== Auto-generated from State Diff =====")
        self.cypher_statements.append(f"// Analysis Time: {self.diff.get('analysis_timestamp')}")

        self._create_account_nodes()

        resources = self.diff.get("resources", {})

        if "IAM" in resources:
            self._process_iam(resources["IAM"])
        if "S3" in resources:
            self._process_s3(resources["S3"])
        if "CLOUDTRAIL" in resources:
            self._process_cloudtrail(resources["CLOUDTRAIL"])

        return self.cypher_statements

    def execute(self, clear_db: bool = False):
        """생성된 Cypher를 Neo4j에 실행"""
        statements = self.generate_cypher()

        print(f"[*] Neo4j 연결 시도 → {self.uri}")
        with self.driver.session(database=self.database) as session:
            if clear_db:
                print("[*] 기존 데이터 삭제 중...")
                session.run("MATCH (n) DETACH DELETE n")

            print("[*] Cypher 실행 중...")
            for stmt in statements:
                # 주석이나 빈 줄은 건너뜀
                clean = stmt.strip()
                if not clean or clean.startswith("//"):
                    continue
                try:
                    session.run(clean)
                except Exception as e:
                    print(f"[!] 실행 실패:\n{clean}\n→ {e}\n")

        print("[+] 완료! Neo4j Browser에서 확인하세요.")
        print("    추천 쿼리:")
        print("    MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 50")

    # ====================== 내부 처리 로직 ======================

    def _create_account_nodes(self):
        self.cypher_statements.append(
            f'MERGE (victim:Account {{account_id: "{self.victim_account}", type: "Target"}})'
        )

    def _process_iam(self, iam_data: Dict):
        roles = iam_data.get("diff", {}).get("roles", {})
        added_roles = roles.get("added", [])

        for role_info in added_roles:
            resource = role_info.get("resource", {})
            role_name = resource.get("role_name")
            role_id = resource.get("role_id")
            arn = resource.get("arn")
            create_date = resource.get("create_date")
            assume_policy = resource.get("assume_role_policy", {})
            attached_policies = resource.get("attached_policies", [])

            external_principal = self._extract_external_principal(assume_policy)
            if external_principal:
                self.attacker_account = external_principal
                self.cypher_statements.append(
                    f'MERGE (attacker:Account {{account_id: "{external_principal}", type: "External"}})'
                )

            ts = self._to_iso(create_date)

            self.cypher_statements.append(f"""
MERGE (role:IAMRole {{
  role_id: "{role_id}",
  role_name: "{role_name}",
  arn: "{arn}",
  created_at: datetime("{ts}")
}})
""")

            if self.attacker_account:
                self.cypher_statements.append(f"""
MERGE (attacker)-[:CREATED_ROLE {{
  timestamp: datetime("{ts}"),
  technique: "T1098.001",
  description: "Malicious IAM Role created"
}}]->(role)
""")

            for pol in attached_policies:
                pol_name = pol.get("PolicyName")
                pol_arn = pol.get("PolicyArn")
                self.cypher_statements.append(f"""
MERGE (policy:ManagedPolicy {{
  policy_name: "{pol_name}",
  policy_arn: "{pol_arn}"
}})
MERGE (role)-[:ATTACHED_POLICY {{
  timestamp: datetime("{ts}")
}}]->(policy)
""")

            self.cypher_statements.append('MERGE (victim)-[:OWNS]->(role)')

    def _process_s3(self, s3_data: Dict):
        changed = s3_data.get("diff", {}).get("changed", [])

        for item in changed:
            bucket_name = item.get("resource_id")
            changes = item.get("changes", [])

            policy_change = next(
                (c for c in changes if c.get("path") == "bucket_policy"), None
            )
            if not policy_change or policy_change.get("after") is None:
                continue

            after_policy = policy_change["after"]
            external = self._extract_principal_from_policy_str(after_policy)
            ts = self._guess_timestamp(s3_data)

            self.cypher_statements.append(f"""
MERGE (bucket:S3Bucket {{
  name: "{bucket_name}",
  arn: "arn:aws:s3:::{bucket_name}"
}})
""")

            attacker_id = external or self.attacker_account
            if attacker_id:
                self.cypher_statements.append(f"""
MERGE (attacker:Account {{account_id: "{attacker_id}", type: "External"}})
MERGE (attacker)-[:GRANTED_S3_ACCESS {{
  timestamp: datetime("{ts}"),
  actions: ["s3:GetObject", "s3:ListBucket"],
  technique: "T1530"
}}]->(bucket)
""")

            self.cypher_statements.append('MERGE (victim)-[:OWNS]->(bucket)')

    def _process_cloudtrail(self, ct_data: Dict):
        changed = ct_data.get("diff", {}).get("changed", [])

        for item in changed:
            trail_arn = item.get("resource_id")
            changes = item.get("changes", [])

            logging_change = next(
                (c for c in changes if c.get("path") == "status.is_logging"), None
            )
            if not logging_change:
                continue

            if logging_change.get("before") is True and logging_change.get("after") is False:
                ts = self._guess_timestamp(ct_data)
                trail_name = trail_arn.split("/")[-1]

                self.cypher_statements.append(f"""
MERGE (trail:CloudTrail {{
  name: "{trail_name}",
  arn: "{trail_arn}"
}})
""")

                if self.attacker_account:
                    self.cypher_statements.append(f"""
MERGE (attacker)-[:STOPPED_LOGGING {{
  timestamp: datetime("{ts}"),
  before: true,
  after: false,
  technique: "T1562.008"
}}]->(trail)
""")

                self.cypher_statements.append('MERGE (victim)-[:OWNS]->(trail)')

    # ====================== Helper ======================

    def _extract_external_principal(self, assume_policy: Dict) -> Optional[str]:
        try:
            for stmt in assume_policy.get("Statement", []):
                principal = stmt.get("Principal", {})
                if "AWS" in principal:
                    arn = principal["AWS"]
                    if isinstance(arn, str) and ":root" in arn:
                        return arn.split(":")[4]
        except Exception:
            pass
        return None

    def _extract_principal_from_policy_str(self, policy_str: str) -> Optional[str]:
        try:
            if "arn:aws:iam::" in policy_str:
                start = policy_str.find("arn:aws:iam::") + len("arn:aws:iam::")
                end = policy_str.find(":", start)
                return policy_str[start:end]
        except Exception:
            pass
        return None

    def _to_iso(self, dt_str: str) -> str:
        if not dt_str:
            return datetime.utcnow().isoformat() + "Z"
        return dt_str.replace(" ", "T").replace("+00:00", "Z")

    def _guess_timestamp(self, resource_data: Dict) -> str:
        ts = resource_data.get("after_timestamp") or resource_data.get("before_timestamp")
        return self._to_iso(ts) if ts else datetime.utcnow().isoformat() + "Z"


# ====================== 실행 ======================
if __name__ == "__main__":
    # 1. Diff JSON 로드
    with open("./diffs/diff_20260907_104650.json", "r", encoding="utf-8") as f:
        diff_data = json.load(f)

    # 2. Neo4j 연결 정보 (본인 환경에 맞게 수정)
    loader = DiffToNeo4j(
        diff_json=diff_data,
        uri="bolt://localhost:7687",
        user="neo4j",
        password="1q2w3e4r!",          # ← 여기 수정!
        database="aws-threat-graph"
    )

    try:
        # clear_db=True 로 하면 기존 데이터를 지우고 새로 넣음
        loader.execute(clear_db=True)
    finally:
        loader.close()