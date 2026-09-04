import json
import os
from src.detector import DiffEngine
from src.ingestor import Neo4jIngestor
from src.resources.s3 import S3Collector
from src.resources.ec2 import EC2Collector
from src.resources.iam import IAMCollector

def process_collector(collector, diff_engine, ingestor, resource_type, arn_prefix):
    baseline_dir = "data"
    items = collector.discover_all()
    print(f"\n=== [{resource_type.upper()}] 리소스 스캔 (총 {len(items)}개) ===")

    for name in items:
        baseline_path = os.path.join(baseline_dir, f"baseline_{resource_type}_{name}.json")
        current_state = collector.get_state(name)

        if not os.path.exists(baseline_path):
            with open(baseline_path, "w") as f:
                json.dump(current_state, f)
            print(f"[{resource_type}:{name}] 초기 Baseline 생성 완료.")
            continue

        with open(baseline_path, "r") as f:
            old_state = json.load(f)

        diffs = diff_engine.extract_changes(old_state, current_state)

        if diffs:
            print(f"[!] {resource_type.upper()} ({name}) 변경점 감지됨!")
            evidence = collector.collect_evidence(name)
            evidence.extend(collector.collect_immutable_trail(name))
            
            arn = f"{arn_prefix}:{name}"
            ingestor.create_change_graph(arn, diffs, evidence)
            
            with open(baseline_path, "w") as f:
                json.dump(current_state, f)
            print(f"[{name}] 그래프 적재 완료.")
        else:
            print(f"[{resource_type.upper()}:{name}] 변경 없음.")

def main():
    diff_engine = DiffEngine()
    ingestor = Neo4jIngestor("bolt://localhost:7687", "neo4j", "YourSecurePassword123")
    os.makedirs("data", exist_ok=True)

    # 리소스별 수집기 인스턴스화
    collectors = [
        (S3Collector(), "s3", "arn:aws:s3:::"),
        (EC2Collector(), "ec2", "arn:aws:ec2:instance"),
        (IAMCollector(), "iam", "arn:aws:iam::role")
    ]

    for collector, rtype, arn_prefix in collectors:
        process_collector(collector, diff_engine, ingestor, rtype, arn_prefix)

    ingestor.close()
    print("\n모든 리소스 검사 완료.")

if __name__ == "__main__":
    main()