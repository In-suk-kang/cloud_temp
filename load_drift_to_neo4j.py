import json
from neo4j import GraphDatabase
from datetime import datetime

class UniversalNeo4jDriftIngestor:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="YourSecurePassword123"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def ingest_drift_data(self, json_file_path):
        with open(json_file_path, 'r', encoding='utf-8') as f:
            drift_data = json.load(f)

        # 확장된 범용 MITRE ATT&CK 전술 매핑 (필요 시 계속 추가 가능)
        tactic_map = {
            'CLOUDTRAIL': 'Defense Evasion',
            'S3': 'Exfiltration / Impact',
            'IAM': 'Persistence / Privilege Escalation',
            'EC2': 'Execution / Resource Hijacking',
            'SECRETSMANAGER': 'Credential Access',
            'KMS': 'Impact',
            'SQS': 'Discovery / C2'
        }

        with self.driver.session() as session:
            # 1. 블라인드 스팟 시간대의 가상 공격자 노드 생성
            session.run("""
                MERGE (a:Attacker {id: 'Unknown_Attacker'})
                ON CREATE SET a.description = 'CloudTrail Disabled Phase'
            """)

            # 2. 모든 행위(Created, Modified, Destroyed) 동적 순회
            for action in ['created', 'modified', 'destroyed']:
                items = drift_data.get(action, [])
                
                for item in items:
                    res_type = item.get('type', 'UNKNOWN').upper()
                    res_id = item.get('id', 'Unknown_ID')
                    tactic = tactic_map.get(res_type, 'Lateral Movement / Execution')
                    
                    # id와 type을 제외한 나머지 가변 속성(from, to, state 등)을 묶어 단일 JSON 문자열로 압축
                    details_dict = {k: v for k, v in item.items() if k not in ['type', 'id']}
                    details_json = json.dumps(details_dict, ensure_ascii=False)

                    # Cypher 쿼리 내 Relationship(엣지) 이름은 파라미터화할 수 없으므로 동적 문자열 포맷팅 사용
                    rel_type = action.upper()
                    
                    query = f"""
                    MATCH (a:Attacker {{id: 'Unknown_Attacker'}})
                    
                    // 리소스 노드 생성 (UPSERT)
                    MERGE (r:Resource {{id: $res_id}})
                    ON CREATE SET r.type = $res_type, r.tactic = $tactic
                    
                    // 공격자 -> 리소스로 향하는 동적 엣지 연결 (CREATED, MODIFIED, DESTROYED)
                    MERGE (a)-[rel:{rel_type}]->(r)
                    SET rel.details = $details,
                        rel.ingested_at = $timestamp
                    """
                    
                    session.run(query, 
                                res_id=res_id, 
                                res_type=res_type, 
                                tactic=tactic, 
                                details=details_json,
                                timestamp=datetime.now().isoformat())
                    
            print("범용 Drift 데이터 Neo4j 적재 완료.")

if __name__ == "__main__":
    ingestor = UniversalNeo4jDriftIngestor(uri="bolt://localhost:7687", user="neo4j", password="YourSecurePassword123")
    ingestor.ingest_drift_data("drift_result.json")
    ingestor.close()