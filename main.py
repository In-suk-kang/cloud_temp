import json
import os
from src.detector import GeneralAWSDriftDetector
from src.ingestor import UniversalNeo4jDriftIngestor

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    
    detector = GeneralAWSDriftDetector()

    # 1. 공격 전 Snapshot 수집
    print("[1] 공격 전 AWS 상태 수집 중...")
    snap_before = detector.take_snapshot()
    detector.save_snapshot(snap_before, "snapshot_before.json")
    print("data/snapshot_before.json 저장 완료\n")

    # 2. 콘솔 공격 대기
    input("터미널 콘솔에서 Stratus Red Team 공격을 수행한 후 Enter를 누르세요...")

    # 3. 공격 후 Snapshot 수집
    print("\n[2] 공격 후 AWS 상태 수집 중...")
    snap_after = detector.take_snapshot()
    detector.save_snapshot(snap_after, "snapshot_after.json")
    print("data/snapshot_after.json 저장 완료\n")

    # 4. Drift 분석 수행
    print("[3] 범용 Drift 분석 수행 중...")
    drift_result = detector.compare(snap_before, snap_after)
    
    drift_result_path = os.path.join("data", "drift_result.json")
    with open(drift_result_path, "w", encoding="utf-8") as f:
        json.dump(drift_result, f, indent=2, ensure_ascii=False)

    print("data/drift_result.json 저장 완료\n")

    # 5. Neo4j 그래프 적재
    print("[4] Neo4j 그래프 DB 적재 및 인과관계 매핑 중...")
    ingestor = UniversalNeo4jDriftIngestor(
        uri="bolt://localhost:7687", 
        user="neo4j", 
        password="YourSecurePassword123"
    )
    ingestor.ingest_drift_data("drift_result.json")
    ingestor.close()
    
    print("\n모든 파이프라인이 성공적으로 완료되었습니다!")