"""
snapshot diff (before/after) -> Neo4j 적재용 정규화 스크립트

입력: analysis_timestamp/resources 구조를 가진 diff JSON
출력:
  - nodes_resources.csv   : 리소스 노드
  - nodes_entities.csv    : ARN/계정ID 등 추출된 엔티티 노드 (Account, Policy 등)
  - events.csv            : 정규화된 변경 이벤트 (ChangeEvent 노드)
  - rel_resource_event.csv    : (Resource)-[:HAS_EVENT]->(ChangeEvent)
  - rel_resource_entity.csv   : (Resource)-[:REFERENCES]->(Entity)  (예: TRUSTS, GRANTS_ACCESS_TO)

사용법:
  python normalize_diff.py diff.json ./out_dir
"""

import json
import re
import sys
import csv
import hashlib
from pathlib import Path

# ---------------------------------------------------------------------------
# 1. 노이즈 필드 필터 (AWS API 호출마다 값이 바뀌는, 보안적으로 무의미한 필드)
# ---------------------------------------------------------------------------
NOISE_PATH_PATTERNS = [
    r"ResponseMetadata",
    r"HTTPHeaders",
    r"x-amz-request-id",
    r"x-amz-id-2",
    r"HostId",
    r"RequestId",
    r"^date$",
]
NOISE_RE = re.compile("|".join(NOISE_PATH_PATTERNS), re.IGNORECASE)

def is_noise(field_path: str) -> bool:
    return bool(NOISE_RE.search(field_path or ""))

# ---------------------------------------------------------------------------
# 2. 리스크 태깅 규칙 (필요에 맞게 계속 추가하면 됨)
# ---------------------------------------------------------------------------
def tag_risk(resource_type, field_path, before, after):
    tags = []
    blob = json.dumps({"path": field_path, "before": before, "after": after}, default=str)

    if resource_type == "IAM" and "AdministratorAccess" in blob:
        tags.append("PRIVILEGE_ESCALATION")
    if resource_type == "CLOUDTRAIL" and field_path.endswith("is_logging") and after is False:
        tags.append("DEFENSE_EVASION_LOGGING_DISABLED")
    if resource_type == "S3" and field_path == "bucket_policy" and before is None and after:
        tags.append("S3_POLICY_GRANTED")
    if re.search(r'"AWS":\s*"arn:aws:iam::\d+:root"', blob):
        tags.append("EXTERNAL_PRINCIPAL_TRUST")
    return tags

# ---------------------------------------------------------------------------
# 3. ARN / 계정ID 추출 (그래프 엣지의 핵심 연결 키)
# ---------------------------------------------------------------------------
ARN_RE = re.compile(r"arn:aws:[a-zA-Z0-9\-]+:[a-zA-Z0-9\-]*:\d{12}:[^\s\"'\\]+")
ACCOUNT_RE = re.compile(r"\b\d{12}\b")

def extract_entities(before, after):
    blob = json.dumps({"before": before, "after": after}, default=str)
    arns = set(ARN_RE.findall(blob))
    accounts = set(ACCOUNT_RE.findall(blob))
    entities = []
    for arn in arns:
        entities.append(("ARN", arn))
    for acct in accounts:
        entities.append(("ACCOUNT", acct))
    return entities

def rel_type_for_entity(entity_type, risk_tags):
    if "EXTERNAL_PRINCIPAL_TRUST" in risk_tags:
        return "TRUSTS"
    if "S3_POLICY_GRANTED" in risk_tags:
        return "GRANTS_ACCESS_TO"
    return "REFERENCES"

# ---------------------------------------------------------------------------
# 4. 평탄화: added/removed/changed 구조를 공통 이벤트 리스트로 변환
# ---------------------------------------------------------------------------
def event_id(*parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]

def walk_changed_list(node, prefix=""):
    """resources.<TYPE>.diff 안의 {added, removed, changed} 혹은
    IAM처럼 {users:{added,removed,changed}, roles:{...}} 형태를 모두 지원."""
    out = []
    if isinstance(node, dict) and {"added", "removed", "changed"} <= set(node.keys()):
        for item in node.get("added", []):
            out.append(("ADDED", item.get("resource_id"), None, None, item.get("resource")))
        for item in node.get("removed", []):
            out.append(("REMOVED", item.get("resource_id"), None, item.get("resource"), None))
        for item in node.get("changed", []):
            rid = item.get("resource_id")
            for ch in item.get("changes", []):
                out.append((ch.get("type", "CHANGED"), rid, ch.get("path"), ch.get("before"), ch.get("after")))
    elif isinstance(node, dict):
        # 하위 카테고리(users/groups/roles 등)를 재귀 처리
        for k, v in node.items():
            out.extend(walk_changed_list(v, prefix=f"{prefix}.{k}" if prefix else k))
    return out

def normalize(diff_json):
    resources_rows = []
    events_rows = []
    entity_rows = {}   # key -> (type, value)
    rel_resource_event = []
    rel_resource_entity = []

    ts = diff_json.get("analysis_timestamp")

    for rtype, rblock in diff_json.get("resources", {}).items():
        after_ts = rblock.get("after_timestamp", ts)
        diff = rblock.get("diff", {})
        raw_events = walk_changed_list(diff)

        for change_type, rid, field_path, before, after in raw_events:
            if rid is None:
                continue
            resources_rows.append({"resource_id": rid, "resource_type": rtype})

            noise = is_noise(field_path or "")

            # 노이즈 필드(ResponseMetadata 등)는 그래프에 올릴 가치가 없으므로
            # 여기서 완전히 스킵한다. 감사 추적이 필요하면 원본 JSON을 별도 보관.
            if noise:
                continue

            risk_tags = tag_risk(rtype, field_path or "", before, after)
            eid = event_id(rtype, rid, field_path, change_type, after_ts)

            events_rows.append({
                "event_id": eid,
                "resource_type": rtype,
                "resource_id": rid,
                "change_type": change_type,
                "field_path": field_path or "(whole_resource)",
                "before": json.dumps(before, default=str) if not isinstance(before, str) else before,
                "after": json.dumps(after, default=str) if not isinstance(after, str) else after,
                "timestamp": after_ts,
                "risk_tags": ";".join(risk_tags),
            })
            rel_resource_event.append({"resource_id": rid, "event_id": eid})

            for etype, eval_ in extract_entities(before, after):
                key = f"{etype}:{eval_}"
                entity_rows[key] = {"entity_type": etype, "value": eval_}
                rel_resource_entity.append({
                    "resource_id": rid,
                    "entity_key": key,
                    "rel_type": rel_type_for_entity(etype, risk_tags),
                    "event_id": eid,
                })

    # 리소스 중복 제거
    dedup_resources = {r["resource_id"]: r for r in resources_rows}

    return {
        "resources": list(dedup_resources.values()),
        "entities": [{"entity_key": k, **v} for k, v in entity_rows.items()],
        "events": events_rows,
        "rel_resource_event": rel_resource_event,
        "rel_resource_entity": rel_resource_entity,
    }

# ---------------------------------------------------------------------------
# 5. CSV 출력 (Neo4j LOAD CSV / neo4j-admin import 로 바로 사용 가능)
# ---------------------------------------------------------------------------
def write_csv(path, rows):
    if not rows:
        return
    keys = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)

def main():
    if len(sys.argv) < 3:
        print("usage: python normalize_diff.py <diff.json> <out_dir>")
        sys.exit(1)

    src, out_dir = sys.argv[1], Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(src, encoding="utf-8") as f:
        diff_json = json.load(f)

    norm = normalize(diff_json)

    write_csv(out_dir / "nodes_resources.csv", norm["resources"])
    write_csv(out_dir / "nodes_entities.csv", norm["entities"])
    write_csv(out_dir / "events.csv", norm["events"])
    write_csv(out_dir / "rel_resource_event.csv", norm["rel_resource_event"])
    write_csv(out_dir / "rel_resource_entity.csv", norm["rel_resource_entity"])

    print(f"resources={len(norm['resources'])} entities={len(norm['entities'])} "
          f"events={len(norm['events'])} rel_r_e={len(norm['rel_resource_event'])} "
          f"rel_r_ent={len(norm['rel_resource_entity'])}")

if __name__ == "__main__":
    main()
