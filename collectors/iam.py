import boto3
import json
from datetime import datetime, timezone
from pathlib import Path


REGION = "ap-northeast-2"

OUTPUT_DIR = Path("snapshots")
OUTPUT_DIR.mkdir(exist_ok=True)

iam = boto3.client(
    "iam",
    region_name=REGION
)


# ============================================================
# Managed Policy
# ============================================================

def collect_managed_policy(policy):

    policy_arn = policy["PolicyArn"]

    policy_info = iam.get_policy(
        PolicyArn=policy_arn
    )["Policy"]

    default_version_id = policy_info["DefaultVersionId"]

    try:

        version = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=default_version_id
        )

        document = version[
            "PolicyVersion"
        ]["Document"]

    except Exception as e:

        document = {
            "error": str(e)
        }

    return {
        "policy_name":
            policy["PolicyName"],

        "policy_arn":
            policy_arn,

        "policy_id":
            policy_info["PolicyId"],

        "version_id":
            default_version_id,

        "document":
            document
    }


# ============================================================
# IAM User
# ============================================================

def collect_users():

    users = []

    paginator = iam.get_paginator(
        "list_users"
    )

    for page in paginator.paginate():

        for user in page["Users"]:

            username = user["UserName"]

            # ------------------------------------------------
            # Managed Policies
            # ------------------------------------------------

            attached_response = (
                iam.list_attached_user_policies(
                    UserName=username
                )
            )

            attached_policies = []

            for policy in attached_response[
                "AttachedPolicies"
            ]:

                attached_policies.append(
                    collect_managed_policy(
                        policy
                    )
                )

            # ------------------------------------------------
            # Inline Policies
            # ------------------------------------------------

            inline_response = (
                iam.list_user_policies(
                    UserName=username
                )
            )

            inline_policies = []

            for policy_name in inline_response[
                "PolicyNames"
            ]:

                response = iam.get_user_policy(
                    UserName=username,
                    PolicyName=policy_name
                )

                inline_policies.append({

                    "policy_name":
                        policy_name,

                    "document":
                        response["PolicyDocument"]
                })

            # ------------------------------------------------
            # Groups
            # ------------------------------------------------

            group_response = (
                iam.list_groups_for_user(
                    UserName=username
                )
            )

            groups = []

            for group in group_response["Groups"]:

                groups.append({

                    "group_id":
                        group["GroupId"],

                    "group_name":
                        group["GroupName"],

                    "arn":
                        group["Arn"]
                })

            # ------------------------------------------------
            # User 정보
            # ------------------------------------------------

            users.append({

                # Resource Anchor
                "user_id":
                    user["UserId"],

                "user_name":
                    username,

                "arn":
                    user["Arn"],

                "path":
                    user["Path"],

                "create_date":
                    user["CreateDate"].isoformat(),

                # 권한
                "attached_policies":
                    attached_policies,

                "inline_policies":
                    inline_policies,

                "groups":
                    groups
            })

    return users


# ============================================================
# IAM Group
# ============================================================

def collect_groups():

    groups = []

    paginator = iam.get_paginator(
        "list_groups"
    )

    for page in paginator.paginate():

        for group in page["Groups"]:

            group_name = group["GroupName"]

            # ------------------------------------------------
            # Managed Policies
            # ------------------------------------------------

            attached_response = (
                iam.list_attached_group_policies(
                    GroupName=group_name
                )
            )

            attached_policies = []

            for policy in attached_response[
                "AttachedPolicies"
            ]:

                attached_policies.append(
                    collect_managed_policy(
                        policy
                    )
                )

            # ------------------------------------------------
            # Inline Policies
            # ------------------------------------------------

            inline_response = (
                iam.list_group_policies(
                    GroupName=group_name
                )
            )

            inline_policies = []

            for policy_name in inline_response[
                "PolicyNames"
            ]:

                response = iam.get_group_policy(
                    GroupName=group_name,
                    PolicyName=policy_name
                )

                inline_policies.append({

                    "policy_name":
                        policy_name,

                    "document":
                        response["PolicyDocument"]
                })

            # ------------------------------------------------
            # Group 정보
            # ------------------------------------------------

            groups.append({

                "group_id":
                    group["GroupId"],

                "group_name":
                    group_name,

                "arn":
                    group["Arn"],

                "path":
                    group["Path"],

                "create_date":
                    group["CreateDate"].isoformat(),

                "attached_policies":
                    attached_policies,

                "inline_policies":
                    inline_policies
            })

    return groups


# ============================================================
# IAM Role
# ============================================================

def collect_roles():

    roles = []

    paginator = iam.get_paginator(
        "list_roles"
    )

    for page in paginator.paginate():

        for role in page["Roles"]:

            role_name = role["RoleName"]

            # ------------------------------------------------
            # Managed Policies
            # ------------------------------------------------

            attached_response = (
                iam.list_attached_role_policies(
                    RoleName=role_name
                )
            )

            attached_policies = []

            for policy in attached_response[
                "AttachedPolicies"
            ]:

                attached_policies.append(
                    collect_managed_policy(
                        policy
                    )
                )

            # ------------------------------------------------
            # Inline Policies
            # ------------------------------------------------

            inline_response = (
                iam.list_role_policies(
                    RoleName=role_name
                )
            )

            inline_policies = []

            for policy_name in inline_response[
                "PolicyNames"
            ]:

                response = iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )

                inline_policies.append({

                    "policy_name":
                        policy_name,

                    "document":
                        response["PolicyDocument"]
                })

            # ------------------------------------------------
            # Role 정보
            # ------------------------------------------------

            roles.append({

                # Resource Anchor
                "role_id":
                    role["RoleId"],

                "role_name":
                    role_name,

                "arn":
                    role["Arn"],

                "path":
                    role["Path"],

                "create_date":
                    role["CreateDate"].isoformat(),

                # Trust Policy
                "trust_policy":
                    role[
                        "AssumeRolePolicyDocument"
                    ],

                # 권한
                "attached_policies":
                    attached_policies,

                "inline_policies":
                    inline_policies
            })

    return roles


# ============================================================
# IAM Snapshot
# ============================================================

def collect_snapshot():

    snapshot = {

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "resource_type":
            "IAM",

        "resources": {

            "users":
                collect_users(),

            "groups":
                collect_groups(),

            "roles":
                collect_roles()
        }
    }

    return snapshot


# ============================================================
# Save
# ============================================================

def save_snapshot(snapshot):

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        OUTPUT_DIR /
        f"iam_{timestamp}.json"
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
            ensure_ascii=False,
            default=str
        )

    print(
        f"[+] IAM snapshot saved: {filename}"
    )


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("IAM RESOURCE COLLECTION")
    print("=" * 60)

    snapshot = collect_snapshot()

    print(
        f"[+] Users  : "
        f"{len(snapshot['resources']['users'])}"
    )

    print(
        f"[+] Groups : "
        f"{len(snapshot['resources']['groups'])}"
    )

    print(
        f"[+] Roles  : "
        f"{len(snapshot['resources']['roles'])}"
    )

    save_snapshot(snapshot)

    print("[+] Collection complete")