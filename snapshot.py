import boto3
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from botocore.exceptions import ClientError


# ============================================================
# Configuration
# ============================================================

REGION = "ap-northeast-2"

BASE_DIR = Path(__file__).parent
SNAPSHOT_DIR = BASE_DIR / "snapshots"


# ============================================================
# AWS Clients
# ============================================================

iam = boto3.client(
    "iam",
    region_name=REGION
)

ec2 = boto3.client(
    "ec2",
    region_name=REGION
)

s3 = boto3.client(
    "s3",
    region_name=REGION
)

cloudtrail = boto3.client(
    "cloudtrail",
    region_name=REGION
)


# ============================================================
# Utility
# ============================================================

def iso_time():
    return datetime.now(
        timezone.utc
    ).isoformat()


def tags_to_dict(tags):
    return {
        tag["Key"]: tag["Value"]
        for tag in tags
    }


def safe_call(func, default=None):

    try:
        return func()

    except ClientError as e:

        print(
            f"    [!] AWS API error: {e}"
        )

        return default


def save_json(data, filename):

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            data,
            f,
            indent=2,
            ensure_ascii=False,
            default=str
        )


# ============================================================
# IAM
# ============================================================

def collect_iam():

    print("[1/6] Collecting IAM...")

    users = []
    groups = []
    roles = []

    # --------------------------------------------------------
    # Users
    # --------------------------------------------------------

    paginator = iam.get_paginator(
        "list_users"
    )

    for page in paginator.paginate():

        for user in page["Users"]:

            user_id = user["UserId"]
            user_name = user["UserName"]

            attached = safe_call(
                lambda:
                iam.list_attached_user_policies(
                    UserName=user_name
                ),
                {"AttachedPolicies": []}
            )

            inline = safe_call(
                lambda:
                iam.list_user_policies(
                    UserName=user_name
                ),
                {"PolicyNames": []}
            )

            users.append({

                "user_id":
                    user_id,

                "user_name":
                    user_name,

                "arn":
                    user.get("Arn"),

                "path":
                    user.get("Path"),

                "create_date":
                    user.get("CreateDate"),

                "attached_policies":
                    attached.get(
                        "AttachedPolicies",
                        []
                    ),

                "inline_policies":
                    inline.get(
                        "PolicyNames",
                        []
                    )
            })

    # --------------------------------------------------------
    # Groups
    # --------------------------------------------------------

    paginator = iam.get_paginator(
        "list_groups"
    )

    for page in paginator.paginate():

        for group in page["Groups"]:

            group_id = group["GroupId"]
            group_name = group["GroupName"]

            attached = safe_call(
                lambda:
                iam.list_attached_group_policies(
                    GroupName=group_name
                ),
                {"AttachedPolicies": []}
            )

            inline = safe_call(
                lambda:
                iam.list_group_policies(
                    GroupName=group_name
                ),
                {"PolicyNames": []}
            )

            groups.append({

                "group_id":
                    group_id,

                "group_name":
                    group_name,

                "arn":
                    group.get("Arn"),

                "path":
                    group.get("Path"),

                "create_date":
                    group.get("CreateDate"),

                "attached_policies":
                    attached.get(
                        "AttachedPolicies",
                        []
                    ),

                "inline_policies":
                    inline.get(
                        "PolicyNames",
                        []
                    )
            })

    # --------------------------------------------------------
    # Roles
    # --------------------------------------------------------

    paginator = iam.get_paginator(
        "list_roles"
    )

    for page in paginator.paginate():

        for role in page["Roles"]:

            role_id = role["RoleId"]
            role_name = role["RoleName"]

            attached = safe_call(
                lambda:
                iam.list_attached_role_policies(
                    RoleName=role_name
                ),
                {"AttachedPolicies": []}
            )

            inline = safe_call(
                lambda:
                iam.list_role_policies(
                    RoleName=role_name
                ),
                {"PolicyNames": []}
            )

            roles.append({

                "role_id":
                    role_id,

                "role_name":
                    role_name,

                "arn":
                    role.get("Arn"),

                "path":
                    role.get("Path"),

                "create_date":
                    role.get("CreateDate"),

                "assume_role_policy":
                    role.get(
                        "AssumeRolePolicyDocument"
                    ),

                "attached_policies":
                    attached.get(
                        "AttachedPolicies",
                        []
                    ),

                "inline_policies":
                    inline.get(
                        "PolicyNames",
                        []
                    )
            })

    print(
        f"    Users: {len(users)}"
    )

    print(
        f"    Groups: {len(groups)}"
    )

    print(
        f"    Roles: {len(roles)}"
    )

    return {
        "timestamp": iso_time(),
        "resource_type": "IAM",
        "resources": {
            "users": users,
            "groups": groups,
            "roles": roles
        }
    }


# ============================================================
# Security Group
# ============================================================

def collect_security_groups():

    print("[2/6] Collecting Security Groups...")

    response = ec2.describe_security_groups()

    resources = []

    for sg in response["SecurityGroups"]:

        def collect_rules(rules):

            result = []

            for rule in rules:

                result.append({

                    "protocol":
                        rule.get("IpProtocol"),

                    "from_port":
                        rule.get("FromPort"),

                    "to_port":
                        rule.get("ToPort"),

                    "ipv4_ranges":
                        rule.get(
                            "IpRanges",
                            []
                        ),

                    "ipv6_ranges":
                        rule.get(
                            "Ipv6Ranges",
                            []
                        ),

                    "prefix_lists":
                        rule.get(
                            "PrefixListIds",
                            []
                        ),

                    "security_groups":
                        rule.get(
                            "UserIdGroupPairs",
                            []
                        )
                })

            return result

        resources.append({

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

            "ingress":
                collect_rules(
                    sg.get(
                        "IpPermissions",
                        []
                    )
                ),

            "egress":
                collect_rules(
                    sg.get(
                        "IpPermissionsEgress",
                        []
                    )
                ),

            "tags":
                tags_to_dict(
                    sg.get("Tags", [])
                )
        })

    print(
        f"    Security Groups: {len(resources)}"
    )

    return {
        "timestamp": iso_time(),
        "resource_type": "SECURITY_GROUP",
        "resources": resources
    }


# ============================================================
# EC2
# ============================================================

def collect_ec2():

    print("[3/6] Collecting EC2...")

    resources = []

    paginator = ec2.get_paginator(
        "describe_instances"
    )

    for page in paginator.paginate():

        for reservation in page["Reservations"]:

            for instance in reservation["Instances"]:

                network_interfaces = []

                for eni in instance.get(
                    "NetworkInterfaces",
                    []
                ):

                    network_interfaces.append({

                        "network_interface_id":
                            eni.get(
                                "NetworkInterfaceId"
                            ),

                        "subnet_id":
                            eni.get("SubnetId"),

                        "vpc_id":
                            eni.get("VpcId"),

                        "private_ip":
                            eni.get("PrivateIpAddress"),

                        "private_dns":
                            eni.get(
                                "PrivateDnsName"
                            ),

                        "interface_type":
                            eni.get("InterfaceType"),

                        "status":
                            eni.get("Status"),

                        "mac_address":
                            eni.get("MacAddress"),

                        "security_groups":
                            eni.get(
                                "Groups",
                                []
                            )
                    })

                block_devices = []

                for device in instance.get(
                    "BlockDeviceMappings",
                    []
                ):

                    ebs = device.get(
                        "Ebs",
                        {}
                    )

                    block_devices.append({

                        "device_name":
                            device.get(
                                "DeviceName"
                            ),

                        "volume_id":
                            ebs.get(
                                "VolumeId"
                            ),

                        "delete_on_termination":
                            ebs.get(
                                "DeleteOnTermination"
                            ),

                        "status":
                            ebs.get(
                                "Status"
                            ),

                        "attach_time":
                            ebs.get(
                                "AttachTime"
                            )
                    })

                resources.append({

                    "instance_id":
                        instance["InstanceId"],

                    "launch_time":
                        instance.get("LaunchTime"),

                    "instance_type":
                        instance.get(
                            "InstanceType"
                        ),

                    "image_id":
                        instance.get("ImageId"),

                    "architecture":
                        instance.get(
                            "Architecture"
                        ),

                    "platform":
                        instance.get("Platform"),

                    "platform_details":
                        instance.get(
                            "PlatformDetails"
                        ),

                    "state": {
                        "code":
                            instance.get(
                                "State",
                                {}
                            ).get("Code"),

                        "name":
                            instance.get(
                                "State",
                                {}
                            ).get("Name")
                    },

                    "availability_zone":
                        instance.get(
                            "Placement",
                            {}
                        ).get(
                            "AvailabilityZone"
                        ),

                    "tenancy":
                        instance.get(
                            "Placement",
                            {}
                        ).get("Tenancy"),

                    "subnet_id":
                        instance.get("SubnetId"),

                    "vpc_id":
                        instance.get("VpcId"),

                    "private_ip":
                        instance.get(
                            "PrivateIpAddress"
                        ),

                    "public_ip":
                        instance.get(
                            "PublicIpAddress"
                        ),

                    "private_dns":
                        instance.get(
                            "PrivateDnsName"
                        ),

                    "public_dns":
                        instance.get(
                            "PublicDnsName"
                        ),

                    "security_groups":
                        instance.get(
                            "SecurityGroups",
                            []
                        ),

                    "network_interfaces":
                        network_interfaces,

                    "iam_instance_profile":
                        instance.get(
                            "IamInstanceProfile"
                        ),

                    "block_devices":
                        block_devices,

                    "monitoring":
                        instance.get(
                            "Monitoring"
                        ),

                    "key_name":
                        instance.get("KeyName"),

                    "tags":
                        tags_to_dict(
                            instance.get(
                                "Tags",
                                []
                            )
                        )
                })

    print(
        f"    EC2 Instances: {len(resources)}"
    )

    return {
        "timestamp": iso_time(),
        "resource_type": "EC2",
        "resources": resources
    }


# ============================================================
# S3
# ============================================================

def collect_s3():

    print("[4/6] Collecting S3...")

    resources = []

    response = s3.list_buckets()

    for bucket in response.get(
        "Buckets",
        []
    ):

        name = bucket["Name"]

        # ----------------------------------------------------
        # Region
        # ----------------------------------------------------

        try:

            region = s3.get_bucket_location(
                Bucket=name
            ).get("LocationConstraint")

            if region is None:
                region = "us-east-1"

        except ClientError:

            region = None

        # ----------------------------------------------------
        # Public Access Block
        # ----------------------------------------------------

        try:

            public_access_block = (
                s3.get_public_access_block(
                    Bucket=name
                ).get(
                    "PublicAccessBlockConfiguration"
                )
            )

        except ClientError:

            public_access_block = None

        # ----------------------------------------------------
        # Bucket Policy
        # ----------------------------------------------------

        try:

            policy = s3.get_bucket_policy(
                Bucket=name
            ).get("Policy")

        except ClientError:

            policy = None

        # ----------------------------------------------------
        # ACL
        # ----------------------------------------------------

        try:

            acl = s3.get_bucket_acl(
                Bucket=name
            )

        except ClientError:

            acl = None

        # ----------------------------------------------------
        # Versioning
        # ----------------------------------------------------

        try:

            versioning = s3.get_bucket_versioning(
                Bucket=name
            )

        except ClientError:

            versioning = None

        # ----------------------------------------------------
        # Encryption
        # ----------------------------------------------------

        try:

            encryption = (
                s3.get_bucket_encryption(
                    Bucket=name
                ).get(
                    "ServerSideEncryptionConfiguration"
                )
            )

        except ClientError:

            encryption = None

        # ----------------------------------------------------
        # Tags
        # ----------------------------------------------------

        try:

            tag_response = s3.get_bucket_tagging(
                Bucket=name
            )

            tags = {
                tag["Key"]: tag["Value"]
                for tag in tag_response.get(
                    "TagSet",
                    []
                )
            }

        except ClientError:

            tags = {}

        resources.append({

            # Resource Anchor
            "name":
                name,

            "arn":
                f"arn:aws:s3:::{name}",

            "creation_date":
                bucket.get("CreationDate"),

            "region":
                region,

            "public_access_block":
                public_access_block,

            "bucket_policy":
                policy,

            "acl":
                acl,

            "versioning":
                versioning,

            "encryption":
                encryption,

            "tags":
                tags
        })

    print(
        f"    S3 Buckets: {len(resources)}"
    )

    return {
        "timestamp": iso_time(),
        "resource_type": "S3",
        "resources": resources
    }


# ============================================================
# VPC
# ============================================================

def collect_vpc():

    print("[5/6] Collecting VPC...")

    # --------------------------------------------------------
    # VPC
    # --------------------------------------------------------

    vpcs = []

    response = ec2.describe_vpcs()

    for vpc in response["Vpcs"]:

        vpcs.append({

            "vpc_id":
                vpc["VpcId"],

            "cidr_block":
                vpc.get("CidrBlock"),

            "state":
                vpc.get("State"),

            "is_default":
                vpc.get("IsDefault"),

            "dhcp_options_id":
                vpc.get("DhcpOptionsId"),

            "tags":
                tags_to_dict(
                    vpc.get("Tags", [])
                )
        })

    # --------------------------------------------------------
    # Subnet
    # --------------------------------------------------------

    subnets = []

    paginator = ec2.get_paginator(
        "describe_subnets"
    )

    for page in paginator.paginate():

        for subnet in page["Subnets"]:

            subnets.append({

                "subnet_id":
                    subnet["SubnetId"],

                "vpc_id":
                    subnet.get("VpcId"),

                "cidr_block":
                    subnet.get("CidrBlock"),

                "availability_zone":
                    subnet.get(
                        "AvailabilityZone"
                    ),

                "availability_zone_id":
                    subnet.get(
                        "AvailabilityZoneId"
                    ),

                "state":
                    subnet.get("State"),

                "map_public_ip_on_launch":
                    subnet.get(
                        "MapPublicIpOnLaunch"
                    ),

                "available_ip_count":
                    subnet.get(
                        "AvailableIpAddressCount"
                    ),

                "default_for_az":
                    subnet.get(
                        "DefaultForAz"
                    ),

                "tags":
                    tags_to_dict(
                        subnet.get(
                            "Tags",
                            []
                        )
                    )
            })

    # --------------------------------------------------------
    # Route Tables
    # --------------------------------------------------------

    route_tables = []

    paginator = ec2.get_paginator(
        "describe_route_tables"
    )

    for page in paginator.paginate():

        for table in page["RouteTables"]:

            routes = []

            for route in table.get(
                "Routes",
                []
            ):

                routes.append({

                    "destination_cidr":
                        route.get(
                            "DestinationCidrBlock"
                        ),

                    "destination_ipv6":
                        route.get(
                            "DestinationIpv6CidrBlock"
                        ),

                    "gateway_id":
                        route.get(
                            "GatewayId"
                        ),

                    "nat_gateway_id":
                        route.get(
                            "NatGatewayId"
                        ),

                    "network_interface_id":
                        route.get(
                            "NetworkInterfaceId"
                        ),

                    "transit_gateway_id":
                        route.get(
                            "TransitGatewayId"
                        ),

                    "instance_id":
                        route.get(
                            "InstanceId"
                        ),

                    "vpc_peering_connection_id":
                        route.get(
                            "VpcPeeringConnectionId"
                        ),

                    "state":
                        route.get("State"),

                    "origin":
                        route.get("Origin")
                })

            associations = []

            for association in table.get(
                "Associations",
                []
            ):

                associations.append({

                    "association_id":
                        association.get(
                            "RouteTableAssociationId"
                        ),

                    "subnet_id":
                        association.get(
                            "SubnetId"
                        ),

                    "main":
                        association.get("Main"),

                    "association_state":
                        association.get(
                            "AssociationState"
                        )
                })

            route_tables.append({

                "route_table_id":
                    table["RouteTableId"],

                "vpc_id":
                    table.get("VpcId"),

                "routes":
                    routes,

                "associations":
                    associations,

                "tags":
                    tags_to_dict(
                        table.get(
                            "Tags",
                            []
                        )
                    )
            })

    # --------------------------------------------------------
    # Internet Gateway
    # --------------------------------------------------------

    internet_gateways = []

    response = ec2.describe_internet_gateways()

    for gateway in response[
        "InternetGateways"
    ]:

        attachments = []

        for attachment in gateway.get(
            "Attachments",
            []
        ):

            attachments.append({

                "vpc_id":
                    attachment.get("VpcId"),

                "state":
                    attachment.get("State")
            })

        internet_gateways.append({

            "internet_gateway_id":
                gateway[
                    "InternetGatewayId"
                ],

            "attachments":
                attachments,

            "tags":
                tags_to_dict(
                    gateway.get(
                        "Tags",
                        []
                    )
                )
        })

    # --------------------------------------------------------
    # Network ACL
    # --------------------------------------------------------

    network_acls = []

    paginator = ec2.get_paginator(
        "describe_network_acls"
    )

    for page in paginator.paginate():

        for acl in page["NetworkAcls"]:

            entries = []

            for entry in acl.get(
                "Entries",
                []
            ):

                entries.append({

                    "rule_number":
                        entry.get(
                            "RuleNumber"
                        ),

                    "protocol":
                        entry.get(
                            "Protocol"
                        ),

                    "rule_action":
                        entry.get(
                            "RuleAction"
                        ),

                    "egress":
                        entry.get(
                            "Egress"
                        ),

                    "cidr_block":
                        entry.get(
                            "CidrBlock"
                        ),

                    "ipv6_cidr_block":
                        entry.get(
                            "Ipv6CidrBlock"
                        ),

                    "port_range":
                        entry.get(
                            "PortRange"
                        ),

                    "icmp_type_code":
                        entry.get(
                            "IcmpTypeCode"
                        )
                })

            associations = []

            for association in acl.get(
                "Associations",
                []
            ):

                associations.append({

                    "association_id":
                        association.get(
                            "NetworkAclAssociationId"
                        ),

                    "subnet_id":
                        association.get(
                            "SubnetId"
                        )
                })

            network_acls.append({

                "network_acl_id":
                    acl["NetworkAclId"],

                "vpc_id":
                    acl.get("VpcId"),

                "is_default":
                    acl.get("IsDefault"),

                "entries":
                    entries,

                "associations":
                    associations,

                "tags":
                    tags_to_dict(
                        acl.get(
                            "Tags",
                            []
                        )
                    )
            })

    print(
        f"    VPCs: {len(vpcs)}"
    )

    print(
        f"    Subnets: {len(subnets)}"
    )

    print(
        f"    Route Tables: {len(route_tables)}"
    )

    print(
        f"    Internet Gateways: "
        f"{len(internet_gateways)}"
    )

    print(
        f"    Network ACLs: "
        f"{len(network_acls)}"
    )

    return {

        "timestamp": iso_time(),

        "resource_type":
            "VPC",

        "resources": {

            "vpcs":
                vpcs,

            "subnets":
                subnets,

            "route_tables":
                route_tables,

            "internet_gateways":
                internet_gateways,

            "network_acls":
                network_acls
        }
    }


# ============================================================
# CloudTrail
# ============================================================

def collect_cloudtrail():

    print("[6/6] Collecting CloudTrail...")

    trails = []

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

        trail_identifier = (
            trail_arn
            or trail_name
        )

        # ----------------------------------------------------
        # Trail Status
        # ----------------------------------------------------

        try:

            status = cloudtrail.get_trail_status(
                Name=trail_identifier
            )

            trail_status = {

                "is_logging":
                    status.get(
                        "IsLogging",
                        False
                    ),

                "latest_delivery_time":
                    status.get(
                        "LatestDeliveryTime"
                    ),

                "latest_notification_time":
                    status.get(
                        "LatestNotificationTime"
                    ),

                "latest_cloudwatch_logs_delivery_time":
                    status.get(
                        "LatestCloudWatchLogsDeliveryTime"
                    ),

                "latest_cloudwatch_logs_delivery_error":
                    status.get(
                        "LatestCloudWatchLogsDeliveryError"
                    ),

                "latest_delivery_error":
                    status.get(
                        "LatestDeliveryError"
                    ),

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

            trail_status = {

                "is_logging":
                    None,

                "error":
                    str(e)
            }

        # ----------------------------------------------------
        # Event Selectors
        # ----------------------------------------------------

        try:

            selectors = cloudtrail.get_event_selectors(
                TrailName=trail_identifier
            )

            event_selectors = {

                "event_selectors":
                    selectors.get(
                        "EventSelectors",
                        []
                    ),

                "advanced_event_selectors":
                    selectors.get(
                        "AdvancedEventSelectors",
                        []
                    )
            }

        except ClientError:

            event_selectors = {}

        # ----------------------------------------------------
        # Insight Selectors
        # ----------------------------------------------------

        try:

            insights = cloudtrail.get_insight_selectors(
                TrailName=trail_identifier
            )

            insight_selectors = insights.get(
                "InsightSelectors",
                []
            )

        except ClientError:

            insight_selectors = []

        trails.append({

            "trail_arn":
                trail_arn,

            "name":
                trail_name,

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

            "log_file_validation_enabled":
                trail.get(
                    "LogFileValidationEnabled"
                ),

            "kms_key_id":
                trail.get(
                    "KMSKeyId"
                ),

            "cloudwatch_logs_log_group_arn":
                trail.get(
                    "CloudWatchLogsLogGroupArn"
                ),

            "cloudwatch_logs_role_arn":
                trail.get(
                    "CloudWatchLogsRoleArn"
                ),

            "sns_topic_arn":
                trail.get(
                    "SnsTopicARN"
                ),

            "has_custom_event_selectors":
                trail.get(
                    "HasCustomEventSelectors"
                ),

            "has_insight_selectors":
                trail.get(
                    "HasInsightSelectors"
                ),

            "event_selectors":
                event_selectors,

            "insight_selectors":
                insight_selectors,

            "status":
                trail_status
        })

    for trail in trails:

        print(
            f"    {trail['name']} "
            f"-> Logging: "
            f"{trail['status'].get('is_logging')}"
        )

    return {

        "timestamp": iso_time(),

        "resource_type":
            "CLOUDTRAIL",

        "resources":
            trails
    }


# ============================================================
# Snapshot
# ============================================================

def collect_all():

    print()
    print("=" * 60)
    print("AWS RESOURCE SNAPSHOT")
    print("=" * 60)
    print()

    start_time = datetime.now(
        timezone.utc
    )

    snapshot = {

        "timestamp":
            start_time.isoformat(),

        "region":
            REGION,

        "resources": {

            "iam":
                collect_iam(),

            "security_group":
                collect_security_groups(),

            "ec2":
                collect_ec2(),

            "s3":
                collect_s3(),

            "vpc":
                collect_vpc(),

            "cloudtrail":
                collect_cloudtrail()
        }
    }

    return snapshot


# ============================================================
# Save
# ============================================================

def save_snapshot(
    snapshot,
    snapshot_type
):

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%d_%H%M%S"
    )

    output_dir = (
        SNAPSHOT_DIR /
        snapshot_type
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    filename = (
        output_dir /
        f"snapshot_{timestamp}.json"
    )

    save_json(
        snapshot,
        filename
    )

    # 개별 파일도 생성
    resources = snapshot[
        "resources"
    ]

    for resource_name, data in resources.items():

        resource_file = (
            output_dir /
            f"{resource_name}.json"
        )

        save_json(
            data,
            resource_file
        )

    print()
    print("=" * 60)
    print(
        f"[+] Snapshot saved"
    )
    print(
        f"[+] Type : {snapshot_type}"
    )
    print(
        f"[+] Path : {output_dir}"
    )
    print("=" * 60)


# ============================================================
# Main
# ============================================================

def main():

    if len(sys.argv) != 2:

        print()
        print(
            "사용법:"
        )

        print()
        print(
            "  python snapshot.py before"
        )

        print(
            "  python snapshot.py after"
        )

        print()

        sys.exit(1)

    snapshot_type = sys.argv[1].lower()

    if snapshot_type not in [
        "before",
        "after"
    ]:

        print(
            "[!] before 또는 after만 "
            "사용할 수 있습니다."
        )

        sys.exit(1)

    try:

        snapshot = collect_all()

        save_snapshot(
            snapshot,
            snapshot_type
        )

        print()
        print(
            "[+] Collection complete!"
        )

    except Exception as e:

        print()
        print(
            f"[!] Snapshot failed: {e}"
        )

        sys.exit(1)


if __name__ == "__main__":

    main()