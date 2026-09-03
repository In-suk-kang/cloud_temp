import json
import os
from neo4j import GraphDatabase
from datetime import datetime

def flatten_dict(d, parent_key='', sep='_'):
    """중첩된 딕셔너리를 1차원 Key/Value로 자동 평탄화"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            # 리스트(배열)는 보기 쉽게 JSON 문자열로 변환하여 저장
            items.append((new_key, json.dumps(v, ensure_ascii=False)))
        else:
            items.append((new_key, v))
    return dict(items)

class UniversalNeo4jDriftIngestor:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="YourSecurePassword123"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def ingest_drift_data(self, filename="drift_result.json"):
        filepath = os.path.join("data", filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            drift_data = json.load(f)

        with self.driver.session() as session:
            # 1. Attacker 노드 생성
            session.run("""
                MERGE (a:Attacker {id: 'Unknown_Attacker'})
                ON CREATE SET a.description = 'CloudTrail Disabled Phase'
            """)

            # 2. 행위(created, modified, destroyed) 순회
            for action in ['created', 'modified', 'destroyed']:
                items = drift_data.get(action, [])
                
                for item in items:
                    res_type = item.get('type', 'UNKNOWN').upper()
                    res_id = item.get('id', 'Unknown_ID')
                    rel_type = action.upper()
                    
                    # [핵심] JSON의 'state' 부분을 자동으로 평탄화
                    raw_state = item.get('state', {})
                    flat_properties = flatten_dict(raw_state)
                    
                    # [핵심] SET r += $props 를 통해 하드코딩 없이 모든 Key/Value 자동 삽입
                    query = f"""
                    MATCH (a:Attacker {{id: 'Unknown_Attacker'}})
                    MERGE (r:Resource {{id: $res_id}})
                    ON CREATE SET r.type = $res_type
                    SET r += $props
                    MERGE (a)-[rel:{rel_type}]->(r)
                    SET rel.ingested_at = $timestamp
                    """
                    
                    session.run(query, 
                                res_id=res_id, 
                                res_type=res_type, 
                                props=flat_properties,
                                timestamp=datetime.now().isoformat())

            print("[Neo4j Ingestor] 자동 정규화 및 적재 완료.")