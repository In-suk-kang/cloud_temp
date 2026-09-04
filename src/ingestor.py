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
            tx.run("""
                MATCH (r:Resource {arn: $arn})
                CREATE (sc:StateChange {
                    timestamp: $timestamp,
                    path: $path,
                    change_type: $change_type,
                    details: $details,
                    base_confidence: 0.3
                })
                CREATE (r)-[:HAS_CHANGE]->(sc)
            """, arn=resource_arn, timestamp=current_time, path=diff['json_path'], 
                 change_type=diff['change_type'], details=diff['details'])

            for ev in evidences:
                tx.run("""
                    MATCH (sc:StateChange {timestamp: $timestamp, path: $path})
                    CREATE (e:Evidence {
                        source: $source, 
                        category: $category, 
                        data: $data
                    })
                    CREATE (sc)-[rel:CORROBORATED_BY {weight: 0.35}]->(e)
                    SET sc.final_confidence = sc.base_confidence + rel.weight
                """, timestamp=current_time, path=diff['json_path'], 
                     source=ev['source'], category=ev['category'], data=ev['data'])