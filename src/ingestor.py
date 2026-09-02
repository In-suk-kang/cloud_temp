import json
from neo4j import GraphDatabase
from datetime import datetime
import os

class UniversalNeo4jDriftIngestor:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="YourSecurePassword123"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def ingest_drift_data(self, filename="drift_result.json"):
        filepath = os.path.join("data", filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            drift_data = json.load(f)

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
            # 1. 블라인드 스팟 가상 공격자 노드 생성
            session.run("""
                MERGE (a:Attacker {id: 'Unknown_Attacker'})
                ON CREATE SET a.description = 'CloudTrail Disabled Phase'
            """)

            # 2. 모든 행위 동적 순회 및 적재
            for action in ['created', 'modified', 'destroyed']:
                items = drift_data.get(action, [])
                
                for item in items:
                    res_type = item.get('type', 'UNKNOWN').upper()
                    res_id = item.get('id', 'Unknown_ID')
                    tactic = tactic_map.get(res_type, 'Lateral Movement / Execution')
                    
                    details_dict = {k: v for k, v in item.items() if k not in ['type', 'id']}
                    details_json = json.dumps(details_dict, ensure_ascii=False)
                    rel_type = action.upper()
                    
                    query = f"""
                    MATCH (a:Attacker {{id: 'Unknown_Attacker'}})
                    MERGE (r:Resource {{id: $res_id}})
                    ON CREATE SET r.type = $res_type, r.tactic = $tactic
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

            # 3. 인과관계 자동 추론 (Defense Evasion -> Impact 연결 엣지 생성)
            session.run("""
                MATCH (evasion:Resource {tactic: 'Defense Evasion'})
                MATCH (impact:Resource) WHERE impact.tactic IN ['Exfiltration / Impact', 'Persistence / Privilege Escalation']
                MERGE (evasion)-[seq:PRECEDES {reason: 'Blind Spot Created Before Attack'}]->(impact)
            """)
            
            print("범용 Drift 데이터 및 인과관계 Neo4j 적재 완료.")