import json
from pathlib import Path
from neo4j import GraphDatabase

# Neo4j 연결 설정 (Aura 또는 Local)
URI = "bolt://localhost:7687"
AUTH = ("neo4j", "YourSecurePassword123")

BASE_DIR = Path(__file__).resolve().parent
DIFFS_DIR = BASE_DIR / "diffs"

def get_latest_diff_file():
    files = sorted(DIFFS_DIR.glob("diff_*.json"))
    if not files:
        raise FileNotFoundError("분석된 diff 파일이 없습니다. diff.py를 먼저 실행하세요.")
    return files[-1]

def load_diff_data(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

def ingest_to_neo4j(tx, resource_name, diff_data):
    """
    Diff 데이터를 분석하여 Neo4j에 노드와 관계를 생성하는 Cypher 쿼리 실행
    """
    if resource_name == "IAM":
        # 추가된 IAM Role 처리
        roles = diff_data.get("diff", {}).get("roles", {})
        for added_role in roles.get("added", []):
            role_id = added_role["resource_id"]
            role = added_role["resource"]
            role_name = role["role_name"]
            arn = role["arn"]
            
            # 1. Role 노드 생성
            query_role = """
            MERGE (r:IAMRole {role_id: $role_id})
            ON CREATE SET r.name = $role_name, r.arn = $arn, r.state = 'ADDED'
            """
            tx.run(query_role, role_id=role_id, role_name=role_name, arn=arn)
            
            # 2. 부착된 정책(Attached Policies) 연결
            for policy in role.get("attached_policies", []):
                policy_name = policy["PolicyName"]
                query_policy = """
                MATCH (r:IAMRole {role_id: $role_id})
                MERGE (p:IAMPolicy {name: $policy_name})
                MERGE (r)-[:ATTACHED_POLICY]->(p)
                """
                tx.run(query_policy, role_id=role_id, policy_name=policy_name)

    elif resource_name == "CLOUDTRAIL":
        # CloudTrail 로깅 상태 변경 처리 (Defense Evasion 탐지)
        changes = diff_data.get("diff", {}).get("changed", [])
        for change in changes:
            trail_arn = change["resource_id"]
            for sub_change in change.get("changes", []):
                if sub_change["path"] == "status.is_logging":
                    before_val = sub_change["before"]
                    after_val = sub_change["after"]
                    
                    query_ct = """
                    MERGE (ct:CloudTrail {arn: $trail_arn})
                    SET ct.is_logging = $after_val
                    CREATE (ct)-[:STATE_DRIFT {type: 'DISABLED_LOGGING', before: $before_val, after: $after_val}]->(s:SecurityAlert {description: 'CloudTrail Logging Stopped'})
                    """
                    tx.run(query_ct, trail_arn=trail_arn, before_val=str(before_val), after_val=str(after_val))

def main():
    diff_file = get_latest_diff_file()
    print(f"[+] Load Diff File: {diff_file}")
    data = load_diff_data(diff_file)
    
    driver = GraphDatabase.driver(URI, auth=AUTH)
    
    with driver.session() as session:
        for resource_name, resource_content in data.get("resources", {}).items():
            print(f"[*] Processing Neo4j ingestion for: {resource_name}")
            session.execute_write(ingest_to_neo4j, resource_name, resource_content)
            
    driver.close()
    print("[+] Neo4j Graph Ingestion Complete!")

if __name__ == "__main__":
    main()