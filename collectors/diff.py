import json
import sys
from pathlib import Path
from datetime import datetime, timezone


SNAPSHOT_DIR = Path("snapshots")
DIFF_DIR = Path("diffs")
DIFF_DIR.mkdir(exist_ok=True)


# ============================================================
# Resource Anchor 정의
# ============================================================

RESOURCE_KEYS = {

    "IAM": {
        "users": "user_id",
        "groups": "group_id",
        "roles": "role_id"
    },

    "SECURITY_GROUP": {
        "resources": "group_id"
    },

    "EC2": {
        "resources": "instance_id"
    },

    "S3": {
        "resources": "name"
    },

    "VPC": {
        "vpcs": "vpc_id",
        "subnets": "subnet_id",
        "route_tables": "route_table_id",
        "internet_gateways": "internet_gateway_id",
        "network_acls": "network_acl_id"
    },

    "CLOUDTRAIL": {
        "resources": "trail_arn"
    }
}


# ============================================================
# JSON 정규화
# ============================================================

def normalize(value):

    if isinstance(value, dict):

        return {
            key: normalize(value[key])
            for key in sorted(value.keys())
        }

    if isinstance(value, list):

        normalized = [
            normalize(item)
            for item in value
        ]

        # 리스트 순서가 중요하지 않은 경우
        try:
            return sorted(
                normalized,
                key=lambda x: json.dumps(
                    x,
                    sort_keys=True,
                    ensure_ascii=False
                )
            )
        except Exception:
            return normalized

    return value


# ============================================================
# Deep Diff
# ============================================================

def deep_diff(before, after, path=""):

    changes = []

    if isinstance(before, dict) and isinstance(after, dict):

        keys = set(before.keys()) | set(after.keys())

        for key in sorted(keys):

            current_path = (
                f"{path}.{key}"
                if path
                else key
            )

            if key not in before:

                changes.append({
                    "type": "ADDED",
                    "path": current_path,
                    "before": None,
                    "after": after[key]
                })

            elif key not in after:

                changes.append({
                    "type": "REMOVED",
                    "path": current_path,
                    "before": before[key],
                    "after": None
                })

            else:

                changes.extend(
                    deep_diff(
                        before[key],
                        after[key],
                        current_path
                    )
                )

    elif before != after:

        changes.append({
            "type": "CHANGED",
            "path": path,
            "before": before,
            "after": after
        })

    return changes


# ============================================================
# Resource Index 생성
# ============================================================

def build_index(resources, key):

    result = {}

    for resource in resources:

        resource_id = resource.get(key)

        if resource_id is not None:

            result[resource_id] = resource

    return result


# ============================================================
# Resource 비교
# ============================================================

def compare_resources(
    before_resources,
    after_resources,
    anchor_key
):

    before_index = build_index(
        before_resources,
        anchor_key
    )

    after_index = build_index(
        after_resources,
        anchor_key
    )

    added = []
    removed = []
    changed = []

    all_ids = (
        set(before_index.keys()) |
        set(after_index.keys())
    )

    for resource_id in sorted(all_ids):

        # --------------------------------------------
        # 새로 생성된 Resource
        # --------------------------------------------

        if resource_id not in before_index:

            added.append({
                "resource_id": resource_id,
                "resource": after_index[resource_id]
            })

            continue

        # --------------------------------------------
        # 삭제된 Resource
        # --------------------------------------------

        if resource_id not in after_index:

            removed.append({
                "resource_id": resource_id,
                "resource": before_index[resource_id]
            })

            continue

        # --------------------------------------------
        # 기존 Resource 변경
        # --------------------------------------------

        before = normalize(
            before_index[resource_id]
        )

        after = normalize(
            after_index[resource_id]
        )

        differences = deep_diff(
            before,
            after
        )

        if differences:

            changed.append({

                "resource_id":
                    resource_id,

                "changes":
                    differences
            })

    return {
        "added": added,
        "removed": removed,
        "changed": changed
    }


# ============================================================
# IAM 비교
# ============================================================

def compare_iam(before, after):

    result = {}

    before_resources = before.get(
        "resources",
        {}
    )

    after_resources = after.get(
        "resources",
        {}
    )

    for resource_type in [
        "users",
        "groups",
        "roles"
    ]:

        result[resource_type] = compare_resources(

            before_resources.get(
                resource_type,
                []
            ),

            after_resources.get(
                resource_type,
                []),

            RESOURCE_KEYS["IAM"][
                resource_type
            ]
        )

    return result


# ============================================================
# 일반 Resource 비교
# ============================================================

def compare_standard(
    before,
    after,
    resource_type
):

    return compare_resources(

        before.get(
            "resources",
            []
        ),

        after.get(
            "resources",
            []),

        RESOURCE_KEYS[resource_type][
            "resources"
        ]
    )


# ============================================================
# VPC 비교
# ============================================================

def compare_vpc(before, after):

    result = {}

    before_resources = before.get(
        "resources",
        {}
    )

    after_resources = after.get(
        "resources",
        {}
    )

    for resource_type in [
        "vpcs",
        "subnets",
        "route_tables",
        "internet_gateways",
        "network_acls"
    ]:

        result[resource_type] = compare_resources(

            before_resources.get(
                resource_type,
                []
            ),

            after_resources.get(
                resource_type,
                []),

            RESOURCE_KEYS["VPC"][
                resource_type
            ]
        )

    return result


# ============================================================
# 전체 Snapshot 비교
# ============================================================

def compare_snapshots(
    before,
    after
):

    resource_type = before.get(
        "resource_type"
    )

    if resource_type != after.get(
        "resource_type"
    ):

        raise ValueError(
            "Snapshot resource_type이 다릅니다."
        )

    if resource_type == "IAM":

        result = compare_iam(
            before,
            after
        )

    elif resource_type == "VPC":

        result = compare_vpc(
            before,
            after
        )

    elif resource_type in RESOURCE_KEYS:

        result = compare_standard(
            before,
            after,
            resource_type
        )

    else:

        raise ValueError(
            f"지원하지 않는 resource_type: "
            f"{resource_type}"
        )

    return {

        "resource_type":
            resource_type,

        "before_timestamp":
            before.get("timestamp"),

        "after_timestamp":
            after.get("timestamp"),

        "diff":
            result
    }


# ============================================================
# Summary
# ============================================================

def print_summary(result):

    print("\n" + "=" * 60)
    print(
        f"STATE DRIFT: "
        f"{result['resource_type']}"
    )
    print("=" * 60)

    def count(data):

        added = 0
        removed = 0
        changed = 0

        if isinstance(data, dict):

            if "added" in data:
                added += len(data["added"])

            if "removed" in data:
                removed += len(data["removed"])

            if "changed" in data:
                changed += len(data["changed"])

            for value in data.values():

                if isinstance(value, dict):

                    a, r, c = count(value)

                    added += a
                    removed += r
                    changed += c

        return added, removed, changed

    added, removed, changed = count(
        result["diff"]
    )

    print(f"[+] Added   : {added}")
    print(f"[+] Removed : {removed}")
    print(f"[+] Changed : {changed}")


# ============================================================
# Main
# ============================================================

def main():

    if len(sys.argv) != 3:

        print(
            "사용법:"
        )

        print(
            "python diff.py "
            "<before.json> <after.json>"
        )

        sys.exit(1)

    before_file = Path(
        sys.argv[1]
    )

    after_file = Path(
        sys.argv[2]
    )

    if not before_file.exists():

        print(
            f"[!] 파일 없음: {before_file}"
        )

        sys.exit(1)

    if not after_file.exists():

        print(
            f"[!] 파일 없음: {after_file}"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    with open(
        before_file,
        "r",
        encoding="utf-8"
    ) as f:

        before = json.load(f)

    with open(
        after_file,
        "r",
        encoding="utf-8"
    ) as f:

        after = json.load(f)

    # --------------------------------------------------------
    # Compare
    # --------------------------------------------------------

    result = compare_snapshots(
        before,
        after
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%d_%H%M%S"
    )

    output_file = (
        DIFF_DIR /
        f"diff_{result['resource_type'].lower()}_{timestamp}.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            result,
            f,
            indent=2,
            ensure_ascii=False
        )

    print_summary(result)

    print(
        f"\n[+] Diff saved: "
        f"{output_file}"
    )


if __name__ == "__main__":
    main()