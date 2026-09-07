import boto3
import json
from datetime import datetime, timezone
from pathlib import Path


REGION = "ap-northeast-2"

OUTPUT_DIR = Path("snapshots")
OUTPUT_DIR.mkdir(exist_ok=True)

ec2 = boto3.client(
    "ec2",
    region_name=REGION
)


# ============================================================
# Security Group Rule
# ============================================================

def collect_rules(rules):

    result = []

    for rule in rules:

        item = {
            "protocol": rule.get("IpProtocol"),

            "from_port": rule.get(
                "FromPort"
            ),

            "to_port": rule.get(
                "ToPort"
            ),

            "ipv4_ranges": [],

            "ipv6_ranges": [],

            "prefix_lists": [],

            "security_group_references": []
        }

        # ----------------------------------------------------
        # IPv4
        # ----------------------------------------------------

        for ip_range in rule.get(
            "IpRanges", []
        ):

            item["ipv4_ranges"].append({
                "cidr":
                    ip_range.get("CidrIp"),

                "description":
                    ip_range.get("Description")
            })

        # ----------------------------------------------------
        # IPv6
        # ----------------------------------------------------

        for ip_range in rule.get(
            "Ipv6Ranges", []
        ):

            item["ipv6_ranges"].append({
                "cidr":
                    ip_range.get("CidrIpv6"),

                "description":
                    ip_range.get("Description")
            })

        # ----------------------------------------------------
        # Prefix List
        # ----------------------------------------------------

        for prefix in rule.get(
            "PrefixListIds", []
        ):

            item["prefix_lists"].append({
                "prefix_list_id":
                    prefix.get("PrefixListId"),

                "description":
                    prefix.get("Description")
            })

        # ----------------------------------------------------
        # 다른 Security Group 참조
        # ----------------------------------------------------

        for group in rule.get(
            "UserIdGroupPairs", []
        ):

            item[
                "security_group_references"
            ].append({

                "group_id":
                    group.get("GroupId"),

                "user_id":
                    group.get("UserId"),

                "vpc_id":
                    group.get("VpcId"),

                "vpc_peering_connection_id":
                    group.get(
                        "VpcPeeringConnectionId"
                    ),

                "description":
                    group.get("Description")
            })

        result.append(item)

    return result


# ============================================================
# Security Group Collection
# ============================================================

def collect_security_groups():

    security_groups = []

    paginator = ec2.get_paginator(
        "describe_security_groups"
    )

    for page in paginator.paginate():

        for sg in page["SecurityGroups"]:

            security_groups.append({

                # ------------------------------------------------
                # Resource Anchor
                # ------------------------------------------------

                "group_id":
                    sg["GroupId"],

                "group_name":
                    sg.get("GroupName"),

                "description":
                    sg.get("Description"),

                "vpc_id":
                    sg.get("VpcId"),

                "owner_id":
                    sg.get("OwnerId"),

                # ------------------------------------------------
                # Ingress
                # ------------------------------------------------

                "ingress":
                    collect_rules(
                        sg.get(
                            "IpPermissions",
                            []
                        )
                    ),

                # ------------------------------------------------
                # Egress
                # ------------------------------------------------

                "egress":
                    collect_rules(
                        sg.get(
                            "IpPermissionsEgress",
                            []
                        )
                    ),

                # ------------------------------------------------
                # Tags
                # ------------------------------------------------

                "tags": {
                    tag["Key"]: tag["Value"]
                    for tag in sg.get(
                        "Tags",
                        []
                    )
                }
            })

    return security_groups


# ============================================================
# Snapshot
# ============================================================

def collect_snapshot():

    return {

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "resource_type":
            "SECURITY_GROUP",

        "resources":
            collect_security_groups()
    }


# ============================================================
# Save Snapshot
# ============================================================

def save_snapshot(snapshot):

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        OUTPUT_DIR /
        f"security_group_{timestamp}.json"
    )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            snapshot,
            f,
            indent=2,
            ensure_ascii=False
        )

    print(
        f"[+] Security Group snapshot saved: "
        f"{filename}"
    )


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("SECURITY GROUP COLLECTION")
    print("=" * 60)

    snapshot = collect_snapshot()

    print(
        f"[+] Security Groups: "
        f"{len(snapshot['resources'])}"
    )

    save_snapshot(snapshot)

    print("[+] Collection complete")