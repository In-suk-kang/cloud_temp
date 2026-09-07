import boto3
import json
from datetime import datetime, timezone
from pathlib import Path


REGION = "ap-northeast-2"

OUTPUT_DIR = Path("snapshots")
OUTPUT_DIR.mkdir(exist_ok=True)

s3 = boto3.client(
    "s3",
    region_name=REGION
)


# ============================================================
# Bucket Policy
# ============================================================

def collect_bucket_policy(bucket_name):

    try:
        response = s3.get_bucket_policy(
            Bucket=bucket_name
        )

        return json.loads(
            response["Policy"]
        )

    except s3.exceptions.ClientError as e:

        error_code = e.response[
            "Error"
        ]["Code"]

        if error_code == "NoSuchBucketPolicy":
            return None

        return {
            "error": str(e)
        }


# ============================================================
# ACL
# ============================================================

def collect_acl(bucket_name):

    try:

        response = s3.get_bucket_acl(
            Bucket=bucket_name
        )

        grants = []

        for grant in response.get(
            "Grants",
            []
        ):

            grantee = grant.get(
                "Grantee",
                {}
            )

            grants.append({

                "permission":
                    grant.get(
                        "Permission"
                    ),

                "grantee": {

                    "type":
                        grantee.get(
                            "Type"
                        ),

                    "id":
                        grantee.get(
                            "ID"
                        ),

                    "display_name":
                        grantee.get(
                            "DisplayName"
                        ),

                    "uri":
                        grantee.get(
                            "URI"
                        )
                }
            })

        return {
            "owner": response.get(
                "Owner"
            ),

            "grants": grants
        }

    except Exception as e:

        return {
            "error": str(e)
        }


# ============================================================
# Public Access Block
# ============================================================

def collect_public_access_block(
    bucket_name
):

    try:

        response = (
            s3.get_public_access_block(
                Bucket=bucket_name
            )
        )

        return response.get(
            "PublicAccessBlockConfiguration"
        )

    except s3.exceptions.ClientError as e:

        error_code = e.response[
            "Error"
        ]["Code"]

        if error_code == "NoSuchPublicAccessBlockConfiguration":
            return None

        return {
            "error": str(e)
        }


# ============================================================
# Encryption
# ============================================================

def collect_encryption(bucket_name):

    try:

        response = (
            s3.get_bucket_encryption(
                Bucket=bucket_name
            )
        )

        rules = []

        for rule in response[
            "ServerSideEncryptionConfiguration"
        ].get("Rules", []):

            rules.append(rule)

        return rules

    except s3.exceptions.ClientError as e:

        error_code = e.response[
            "Error"
        ]["Code"]

        if error_code in [
            "ServerSideEncryptionConfigurationNotFoundError",
            "NoSuchBucket"
        ]:

            return None

        return {
            "error": str(e)
        }


# ============================================================
# Versioning
# ============================================================

def collect_versioning(bucket_name):

    try:

        response = (
            s3.get_bucket_versioning(
                Bucket=bucket_name
            )
        )

        return {
            "status":
                response.get("Status"),

            "mfa_delete":
                response.get("MFADelete")
        }

    except Exception as e:

        return {
            "error": str(e)
        }


# ============================================================
# Tags
# ============================================================

def collect_tags(bucket_name):

    try:

        response = s3.get_bucket_tagging(
            Bucket=bucket_name
        )

        return {
            tag["Key"]: tag["Value"]
            for tag in response.get(
                "TagSet",
                []
            )
        }

    except s3.exceptions.ClientError as e:

        error_code = e.response[
            "Error"
        ]["Code"]

        if error_code == "NoSuchTagSet":
            return {}

        return {
            "error": str(e)
        }


# ============================================================
# Bucket Region
# ============================================================

def collect_bucket_region(
    bucket_name
):

    try:

        response = (
            s3.get_bucket_location(
                Bucket=bucket_name
            )
        )

        location = response.get(
            "LocationConstraint"
        )

        # us-east-1은 LocationConstraint가 None
        if location is None:
            return "us-east-1"

        # 과거 S3 응답 호환
        if location == "EU":
            return "eu-west-1"

        return location

    except Exception as e:

        return {
            "error": str(e)
        }


# ============================================================
# Bucket
# ============================================================

def collect_bucket(bucket):

    bucket_name = bucket[
        "Name"
    ]

    creation_date = bucket.get(
        "CreationDate"
    )

    # --------------------------------------------------------
    # Region
    # --------------------------------------------------------

    region = collect_bucket_region(
        bucket_name
    )

    # --------------------------------------------------------
    # Bucket ARN
    # --------------------------------------------------------

    bucket_arn = (
        f"arn:aws:s3:::{bucket_name}"
    )

    return {

        # ====================================================
        # Resource Anchor
        # ====================================================

        "bucket_name":
            bucket_name,

        "bucket_arn":
            bucket_arn,

        "creation_date":
            (
                creation_date.isoformat()
                if creation_date
                else None
            ),

        "region":
            region,

        # ====================================================
        # Security State
        # ====================================================

        "public_access_block":
            collect_public_access_block(
                bucket_name
            ),

        "bucket_policy":
            collect_bucket_policy(
                bucket_name
            ),

        "acl":
            collect_acl(
                bucket_name
            ),

        # ====================================================
        # Configuration
        # ====================================================

        "versioning":
            collect_versioning(
                bucket_name
            ),

        "encryption":
            collect_encryption(
                bucket_name
            ),

        "tags":
            collect_tags(
                bucket_name
            )
    }


# ============================================================
# S3 Collection
# ============================================================

def collect_buckets():

    buckets = []

    response = s3.list_buckets()

    for bucket in response.get(
        "Buckets",
        []
    ):

        buckets.append(
            collect_bucket(
                bucket
            )
        )

    return buckets


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
            "S3",

        "resources":
            collect_buckets()
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
        f"s3_{timestamp}.json"
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
        f"[+] S3 snapshot saved: "
        f"{filename}"
    )


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("S3 RESOURCE COLLECTION")
    print("=" * 60)

    snapshot = collect_snapshot()

    print(
        f"[+] S3 Buckets: "
        f"{len(snapshot['resources'])}"
    )

    save_snapshot(snapshot)

    print("[+] Collection complete")