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
# Network Interface
# ============================================================

def collect_network_interfaces(instance):

    interfaces = []

    for eni in instance.get(
        "NetworkInterfaces",
        []
    ):

        interfaces.append({

            # Resource Anchor
            "network_interface_id":
                eni.get("NetworkInterfaceId"),

            "subnet_id":
                eni.get("SubnetId"),

            "vpc_id":
                eni.get("VpcId"),

            "private_ip":
                eni.get("PrivateIpAddress"),

            "private_dns":
                eni.get("PrivateDnsName"),

            "interface_type":
                eni.get("InterfaceType"),

            "status":
                eni.get("Status"),

            "mac_address":
                eni.get("MacAddress"),

            # 연결된 Security Group
            "security_groups": [
                {
                    "group_id":
                        sg.get("GroupId"),

                    "group_name":
                        sg.get("GroupName")
                }
                for sg in eni.get(
                    "Groups",
                    []
                )
            ]
        })

    return interfaces


# ============================================================
# Block Device
# ============================================================

def collect_block_devices(instance):

    devices = []

    for device in instance.get(
        "BlockDeviceMappings",
        []
    ):

        ebs = device.get("Ebs")

        if not ebs:
            continue

        devices.append({

            "device_name":
                device.get("DeviceName"),

            "volume_id":
                ebs.get("VolumeId"),

            "delete_on_termination":
                ebs.get(
                    "DeleteOnTermination"
                ),

            "status":
                ebs.get("Status"),

            "attach_time":
                (
                    ebs["AttachTime"].isoformat()
                    if ebs.get("AttachTime")
                    else None
                )
        })

    return devices


# ============================================================
# IAM Instance Profile
# ============================================================

def collect_iam_profile(instance):

    profile = instance.get(
        "IamInstanceProfile"
    )

    if not profile:
        return None

    return {
        "id":
            profile.get("Id"),

        "arn":
            profile.get("Arn")
    }


# ============================================================
# EC2 Instance
# ============================================================

def collect_instance(instance):

    state = instance.get(
        "State",
        {}
    )

    placement = instance.get(
        "Placement",
        {}
    )

    # --------------------------------------------------------
    # Tags
    # --------------------------------------------------------

    tags = {
        tag["Key"]: tag["Value"]
        for tag in instance.get(
            "Tags",
            []
        )
    }

    # --------------------------------------------------------
    # Security Groups
    # --------------------------------------------------------

    security_groups = [
        {
            "group_id":
                sg.get("GroupId"),

            "group_name":
                sg.get("GroupName")
        }
        for sg in instance.get(
            "SecurityGroups",
            []
        )
    ]

    # --------------------------------------------------------
    # Instance 정보
    # --------------------------------------------------------

    return {

        # ====================================================
        # Resource Anchor
        # ====================================================

        "instance_id":
            instance["InstanceId"],

        "launch_time":
            instance["LaunchTime"].isoformat(),

        # ====================================================
        # 기본 정보
        # ====================================================

        "instance_type":
            instance.get("InstanceType"),

        "image_id":
            instance.get("ImageId"),

        "architecture":
            instance.get("Architecture"),

        "platform":
            instance.get("Platform"),

        "platform_details":
            instance.get("PlatformDetails"),

        # ====================================================
        # 상태
        # ====================================================

        "state": {

            "code":
                state.get("Code"),

            "name":
                state.get("Name")
        },

        # ====================================================
        # 위치
        # ====================================================

        "availability_zone":
            placement.get(
                "AvailabilityZone"
            ),

        "tenancy":
            placement.get(
                "Tenancy"
            ),

        "subnet_id":
            instance.get("SubnetId"),

        "vpc_id":
            instance.get("VpcId"),

        # ====================================================
        # Network
        # ====================================================

        "private_ip":
            instance.get(
                "PrivateIpAddress"
            ),

        "private_dns":
            instance.get(
                "PrivateDnsName"
            ),

        "public_ip":
            instance.get(
                "PublicIpAddress"
            ),

        "public_dns":
            instance.get(
                "PublicDnsName"
            ),

        # ====================================================
        # Security Group
        # ====================================================

        "security_groups":
            security_groups,

        # ====================================================
        # ENI
        # ====================================================

        "network_interfaces":
            collect_network_interfaces(
                instance
            ),

        # ====================================================
        # IAM Role / Instance Profile
        # ====================================================

        "iam_instance_profile":
            collect_iam_profile(
                instance
            ),

        # ====================================================
        # Storage
        # ====================================================

        "block_devices":
            collect_block_devices(
                instance
            ),

        # ====================================================
        # Monitoring
        # ====================================================

        "monitoring":
            instance.get(
                "Monitoring",
                {}
            ).get("State"),

        # ====================================================
        # Key Pair
        # ====================================================

        "key_name":
            instance.get("KeyName"),

        # ====================================================
        # Tags
        # ====================================================

        "tags":
            tags
    }


# ============================================================
# EC2 Collection
# ============================================================

def collect_instances():

    instances = []

    paginator = ec2.get_paginator(
        "describe_instances"
    )

    for page in paginator.paginate():

        for reservation in page[
            "Reservations"
        ]:

            for instance in reservation[
                "Instances"
            ]:

                instances.append(
                    collect_instance(
                        instance
                    )
                )

    return instances


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
            "EC2",

        "resources":
            collect_instances()
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
        f"ec2_{timestamp}.json"
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
        f"[+] EC2 snapshot saved: "
        f"{filename}"
    )


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("EC2 RESOURCE COLLECTION")
    print("=" * 60)

    snapshot = collect_snapshot()

    print(
        f"[+] EC2 Instances: "
        f"{len(snapshot['resources'])}"
    )

    save_snapshot(snapshot)

    print("[+] Collection complete")