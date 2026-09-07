import boto3
import json
from datetime import datetime, timezone
from pathlib import Path
from botocore.exceptions import ClientError


REGION = "ap-northeast-2"

OUTPUT_DIR = Path("snapshots")
OUTPUT_DIR.mkdir(exist_ok=True)

cloudtrail = boto3.client(
    "cloudtrail",
    region_name=REGION
)


# ============================================================
# Event Selectors
# ============================================================

def collect_event_selectors(trail_name):

    try:
        response = cloudtrail.get_event_selectors(
            TrailName=trail_name
        )

        return {
            "event_selectors":
                response.get(
                    "EventSelectors", []
                ),

            "advanced_event_selectors":
                response.get(
                    "AdvancedEventSelectors", []
                )
        }

    except ClientError as e:

        return {
            "error": str(e)
        }


# ============================================================
# Insight Selectors
# ============================================================

def collect_insight_selectors(trail_name):

    try:

        response = cloudtrail.get_insight_selectors(
            TrailName=trail_name
        )

        return response.get(
            "InsightSelectors",
            []
        )

    except ClientError:

        return []


# ============================================================
# Trail Status
# ============================================================

def collect_trail_status(trail_name):

    try:

        status = cloudtrail.get_trail_status(
            Name=trail_name
        )

        return {

            # 핵심
            "is_logging":
                status.get(
                    "IsLogging",
                    False
                ),

            # 마지막 로그 전달 시간
            "latest_delivery_time":
                status.get(
                    "LatestDeliveryTime"
                ),

            "latest_notification_time":
                status.get(
                    "LatestNotificationTime"
                ),

            # CloudWatch Logs 전달
            "latest_cloudwatch_logs_delivery_time":
                status.get(
                    "LatestCloudWatchLogsDeliveryTime"
                ),

            "latest_cloudwatch_logs_delivery_error":
                status.get(
                    "LatestCloudWatchLogsDeliveryError"
                ),

            # S3 전달 오류
            "latest_delivery_error":
                status.get(
                    "LatestDeliveryError"
                ),

            # Digest
            "latest_digest_delivery_time":
                status.get(
                    "LatestDigestDeliveryTime"
                ),

            "latest_digest_delivery_error":
                status.get(
                    "LatestDigestDeliveryError"
                )
        }

    except ClientError as e:

        return {
            "is_logging": None,
            "error": str(e)
        }


# ============================================================
# Trail
# ============================================================

def collect_trails():

    trails = []

    try:

        response = cloudtrail.describe_trails(
            includeShadowTrails=True
        )

        for trail in response.get(
            "trailList",
            []
        ):

            trail_name = trail.get(
                "Name"
            )

            trail_arn = trail.get(
                "TrailARN"
            )

            # Logging 상태
            status = collect_trail_status(
                trail_arn or trail_name
            )

            # Event Selector
            selectors = collect_event_selectors(
                trail_arn or trail_name
            )

            # Insight Selector
            insights = collect_insight_selectors(
                trail_arn or trail_name
            )

            trails.append({

                # ==================================================
                # Resource Anchor
                # ==================================================

                "trail_arn":
                    trail_arn,

                "name":
                    trail_name,

                # ==================================================
                # 기본 설정
                # ==================================================

                "home_region":
                    trail.get(
                        "HomeRegion"
                    ),

                "s3_bucket_name":
                    trail.get(
                        "S3BucketName"
                    ),

                "s3_key_prefix":
                    trail.get(
                        "S3KeyPrefix"
                    ),

                # ==================================================
                # Logging 범위
                # ==================================================

                "include_global_service_events":
                    trail.get(
                        "IncludeGlobalServiceEvents"
                    ),

                "is_multi_region_trail":
                    trail.get(
                        "IsMultiRegionTrail"
                    ),

                "is_organization_trail":
                    trail.get(
                        "IsOrganizationTrail"
                    ),

                # ==================================================
                # 보안 / 검증
                # ==================================================

                "log_file_validation_enabled":
                    trail.get(
                        "LogFileValidationEnabled"
                    ),

                "kms_key_id":
                    trail.get(
                        "KMSKeyId"
                    ),

                # ==================================================
                # CloudWatch Logs
                # ==================================================

                "cloudwatch_logs_log_group_arn":
                    trail.get(
                        "CloudWatchLogsLogGroupArn"
                    ),

                "cloudwatch_logs_role_arn":
                    trail.get(
                        "CloudWatchLogsRoleArn"
                    ),

                # ==================================================
                # SNS
                # ==================================================

                "sns_topic_arn":
                    trail.get(
                        "SnsTopicARN"
                    ),

                # ==================================================
                # Selector
                # ==================================================

                "has_custom_event_selectors":
                    trail.get(
                        "HasCustomEventSelectors"
                    ),

                "has_insight_selectors":
                    trail.get(
                        "HasInsightSelectors"
                    ),

                "event_selectors":
                    selectors,

                "insight_selectors":
                    insights,

                # ==================================================
                # Logging 상태
                # ==================================================

                "status":
                    status
            })

    except ClientError as e:

        print(
            f"[!] CloudTrail collection error: {e}"
        )

    return trails


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
            "CLOUDTRAIL",

        "resources":
            collect_trails()
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
        f"cloudtrail_{timestamp}.json"
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
        f"[+] CloudTrail snapshot saved: {filename}"
    )


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("CLOUDTRAIL RESOURCE COLLECTION")
    print("=" * 60)

    snapshot = collect_snapshot()

    trails = snapshot[
        "resources"
    ]

    print(
        f"[+] Trails: {len(trails)}"
    )

    for trail in trails:

        status = trail.get(
            "status",
            {}
        )

        print(
            f"    - {trail.get('name')}"
        )

        print(
            f"      ARN: "
            f"{trail.get('trail_arn')}"
        )

        print(
            f"      Logging: "
            f"{status.get('is_logging')}"
        )

    save_snapshot(snapshot)

    print("[+] Collection complete")