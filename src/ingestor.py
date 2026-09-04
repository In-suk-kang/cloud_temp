from neo4j import GraphDatabase
from datetime import datetime, timezone

class Neo4jIngestor:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def create_change_graph(self, resource_arn, diffs, evidences):
        with self.driver.session() as session:
            session.execute_write(self._merge_graph_tx, resource_arn, diffs, evidences)

    @staticmethod
    def _merge_graph_tx(tx, resource_arn, diffs, evidences):
        current_time = datetime.now(timezone.utc).isoformat()
        
        tx.run("MERGE (r:Resource {arn: $arn})", arn=resource_arn)

        for diff in diffs:
            # 신뢰도(base_confidence) 속성 제거
            tx.run("""
                MATCH (r:Resource {arn: $arn})
                CREATE (sc:StateChange {
                    timestamp: $timestamp,
                    path: $path,
                    change_type: $change_type,
                    before_value: $before_val,
                    after_value: $after_val
                })
                CREATE (r)-[:HAS_CHANGE]->(sc)
            """, arn=resource_arn, timestamp=current_time, path=diff['json_path'], 
                 change_type=diff['change_type'], before_val=diff.get('before_val', ''), 
                 after_val=diff.get('after_val', ''))

            for ev in evidences:
                source_label = ev['source'].replace(' ', '_').upper()
                # 관계선 가중치(weight) 및 final_confidence 업데이트 로직 제거
                query = f"""
                    MATCH (sc:StateChange {{timestamp: $timestamp, path: $path}})
                    CREATE (e:Evidence:{source_label} {{
                        source: $source, 
                        category: $category, 
                        event_name: $event_name,
                        event_time: $event_time,
                        display_name: $display_name
                    }})
                    CREATE (sc)-[:CORROBORATED_BY]->(e)
                """
                tx.run(query, timestamp=current_time, path=diff['json_path'], 
                       source=ev['source'], category=ev['category'], 
                       event_name=ev.get('event_name', ''), 
                       event_time=ev.get('event_time', ''),
                       display_name=ev.get('event_name', ev['source']))