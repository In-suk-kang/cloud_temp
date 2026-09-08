import json
from pathlib import Path
from datetime import datetime


# ============================================================
# 설정
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

BEFORE_DIR = BASE_DIR / "snapshots" / "before"
AFTER_DIR = BASE_DIR / "snapshots" / "after"

OUTPUT_DIR = BASE_DIR / "diffs"


# ============================================================
# Resource Anchor
# ============================================================

RESOURCE_KEYS = {
    "iam": {
        "users": "user_id",
        "groups": "group_id",
        "roles": "role_id"
    },
    "security_group": {
        "resources": "group_id"
    },
    "ec2": {
        "resources": "instance_id"
    },
    "s3": {
        "resources": "name"
    },
    "vpc": {
        "vpcs": "vpc_id",
        "subnets": "subnet_id",
        "route_tables": "route_table_id",
        "internet_gateways": "internet_gateway_id",
        "network_acls": "network_acl_id"
    },
    "cloudtrail": {
        "resources": "trail_arn"
    }
}


# ============================================================
# Noise 제거
# ============================================================

IGNORED_KEYS = {
    "ResponseMetadata"
}


def remove_ignored_fields(obj):
    """
    AWS API 응답에서 State Drift 분석에 필요 없는
    ResponseMetadata를 재귀적으로 제거한다.
    """

    if isinstance(obj, dict):

        return {
            key: remove_ignored_fields(value)
            for key, value in obj.items()
            if key not in IGNORED_KEYS
        }

    elif isinstance(obj, list):

        return [
            remove_ignored_fields(item)
            for item in obj
        ]

    return obj


# ============================================================
# JSON Load
# ============================================================

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_json(directory, prefix):
    """
    directory에서 prefix로 시작하는 JSON 파일을 찾는다.
    """

    files = sorted(directory.glob(f"{prefix}*.json"))

    if not files:
        raise FileNotFoundError(
            f"파일을 찾을 수 없습니다: {directory}/{prefix}*.json"
        )

    return files[-1]


# ============================================================
# Normalize
# ============================================================

def normalize(obj):
    """
    Dictionary key 순서 및 List 순서 차이를 제거한다.
    """

    if isinstance(obj, dict):

        return {
            key: normalize(value)
            for key, value in sorted(obj.items())
        }

    if isinstance(obj, list):

        normalized = [
            normalize(item)
            for item in obj
        ]

        try:
            return sorted(
                normalized,
                key=lambda x: json.dumps(
                    x,
                    sort_keys=True,
                    default=str
                )
            )
        except Exception:
            return normalized

    return obj


# ============================================================
# Deep Diff
# ============================================================

def deep_diff(before, after, path=""):
    changes = []

    # Dictionary
    if isinstance(before, dict) and isinstance(after, dict):

        all_keys = set(before.keys()) | set(after.keys())

        for key in sorted(all_keys):

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

        return changes

    # List
    if isinstance(before, list) and isinstance(after, list):

        before_normalized = normalize(before)
        after_normalized = normalize(after)

        if before_normalized != after_normalized:

            changes.append({
                "type": "CHANGED",
                "path": path,
                "before": before,
                "after": after
            })

        return changes

    # Primitive
    if before != after:

        changes.append({
            "type": "CHANGED",
            "path": path,
            "before": before,
            "after": after
        })

    return changes


# ============================================================
# Resource Index
# ============================================================

def index_resources(resources, key):
    """
    Resource Anchor를 기준으로 dictionary 형태로 변환.
    """

    result = {}

    for resource in resources:

        resource_id = resource.get(key)

        if resource_id is not None:
            result[str(resource_id)] = resource

    return result


# ============================================================
# Resource Diff
# ============================================================

def diff_resource_list(
    before_resources,
    after_resources,
    resource_key
):

    before_map = index_resources(
        before_resources,
        resource_key
    )

    after_map = index_resources(
        after_resources,
        resource_key
    )

    added = []
    removed = []
    changed = []

    # Added
    for resource_id in after_map:

        if resource_id not in before_map:

            added.append({
                "resource_id": resource_id,
                "resource": after_map[resource_id]
            })

    # Removed
    for resource_id in before_map:

        if resource_id not in after_map:

            removed.append({
                "resource_id": resource_id,
                "resource": before_map[resource_id]
            })

    # Changed
    for resource_id in before_map:

        if resource_id not in after_map:
            continue

        before = before_map[resource_id]
        after = after_map[resource_id]

        # 중요:
        # ResponseMetadata 제거 후 비교
        before_clean = remove_ignored_fields(before)
        after_clean = remove_ignored_fields(after)

        changes = deep_diff(
            before_clean,
            after_clean
        )

        if changes:

            changed.append({
                "resource_id": resource_id,
                "changes": changes
            })

    return {
        "added": added,
        "removed": removed,
        "changed": changed
    }


# ============================================================
# IAM
# ============================================================

def diff_iam(before, after):

    result = {}

    for resource_type in [
        "users",
        "groups",
        "roles"
    ]:

        key = RESOURCE_KEYS["iam"][resource_type]

        result[resource_type] = diff_resource_list(
            before.get(resource_type, []),
            after.get(resource_type, []),
            key
        )

    return result


# ============================================================
# Security Group
# ============================================================

def diff_security_group(before, after):

    return diff_resource_list(
        before.get("resources", []),
        after.get("resources", []),
        RESOURCE_KEYS["security_group"]["resources"]
    )


# ============================================================
# EC2
# ============================================================

def diff_ec2(before, after):

    return diff_resource_list(
        before.get("resources", []),
        after.get("resources", []),
        RESOURCE_KEYS["ec2"]["resources"]
    )


# ============================================================
# S3
# ============================================================

def diff_s3(before, after):

    return diff_resource_list(
        before.get("resources", []),
        after.get("resources", []),
        RESOURCE_KEYS["s3"]["resources"]
    )


# ============================================================
# VPC
# ============================================================

def diff_vpc(before, after):

    result = {}

    for resource_type in [
        "vpcs",
        "subnets",
        "route_tables",
        "internet_gateways",
        "network_acls"
    ]:

        key = RESOURCE_KEYS["vpc"][resource_type]

        result[resource_type] = diff_resource_list(
            before.get(resource_type, []),
            after.get(resource_type, []),
            key
        )

    return result


# ============================================================
# CloudTrail
# ============================================================

def diff_cloudtrail(before, after):

    return diff_resource_list(
        before.get("resources", []),
        after.get("resources", []),
        RESOURCE_KEYS["cloudtrail"]["resources"]
    )


# ============================================================
# Resource Type 처리
# ============================================================

def process_resource(
    resource_name,
    before_data,
    after_data
):

    name = resource_name.lower()

    if name == "iam":
        return diff_iam(
            before_data,
            after_data
        )

    elif name == "security_group":
        return diff_security_group(
            before_data,
            after_data
        )

    elif name == "ec2":
        return diff_ec2(
            before_data,
            after_data
        )

    elif name == "s3":
        return diff_s3(
            before_data,
            after_data
        )

    elif name == "vpc":
        return diff_vpc(
            before_data,
            after_data
        )

    elif name == "cloudtrail":
        return diff_cloudtrail(
            before_data,
            after_data
        )

    return {}


# ============================================================
# Summary
# ============================================================

def print_summary(resource_name, diff):

    print()
    print("=" * 70)
    print(f"[{resource_name}]")
    print("=" * 70)

    def count(data):

        if isinstance(data, dict):

            return (
                len(data.get("added", [])),
                len(data.get("removed", [])),
                len(data.get("changed", []))
            )

        return 0, 0, 0

    total_added = 0
    total_removed = 0
    total_changed = 0

    if isinstance(diff, dict):

        for _, value in diff.items():

            added, removed, changed = count(value)

            total_added += added
            total_removed += removed
            total_changed += changed

    print(f"ADDED   : {total_added}")
    print(f"REMOVED : {total_removed}")
    print(f"CHANGED : {total_changed}")


# ============================================================
# Main
# ============================================================

def main():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    resources = {}

    resource_files = {
        "IAM": "iam",
        "SECURITY_GROUP": "security_group",
        "EC2": "ec2",
        "S3": "s3",
        "VPC": "vpc",
        "CLOUDTRAIL": "cloudtrail"
    }

    print()
    print("=" * 70)
    print("AWS State Drift Analysis")
    print("=" * 70)

    for resource_name, prefix in resource_files.items():

        print(f"\n[{resource_name}] 분석 중...")

        try:

            before_file = find_json(
                BEFORE_DIR,
                prefix
            )

            after_file = find_json(
                AFTER_DIR,
                prefix
            )

            before_data = load_json(
                before_file
            )

            after_data = load_json(
                after_file
            )

            # snapshot.py에서 저장한 wrapper 제거
            before_resources = before_data.get(
                "resources",
                before_data
            )

            after_resources = after_data.get(
                "resources",
                after_data
            )

            diff = process_resource(
                resource_name,
                before_resources,
                after_resources
            )

            resources[resource_name] = {
                "resource_type": resource_name,
                "before_timestamp": before_data.get(
                    "timestamp"
                ),
                "after_timestamp": after_data.get(
                    "timestamp"
                ),
                "diff": diff
            }

            print_summary(
                resource_name,
                diff
            )

            # 개별 diff 저장
            individual_output = (
                OUTPUT_DIR /
                f"{prefix}_diff.json"
            )

            with open(
                individual_output,
                "w",
                encoding="utf-8"
            ) as f:

                json.dump(
                    diff,
                    f,
                    indent=2,
                    ensure_ascii=False,
                    default=str
                )

        except Exception as e:

            print(
                f"[ERROR] {resource_name}: {e}"
            )

    # ========================================================
    # 전체 결과
    # ========================================================

    result = {
        "analysis_timestamp": datetime.now().astimezone().isoformat(),
        "before_directory": str(BEFORE_DIR),
        "after_directory": str(AFTER_DIR),
        "resources": resources
    }

    output_file = (
        OUTPUT_DIR /
        f"diff_{timestamp}.json"
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
            ensure_ascii=False,
            default=str
        )
 
    print()
    print("=" * 70)
    print("분석 완료")
    print("=" * 70)
    print(f"전체 결과: {output_file}")
    print(f"개별 결과: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()