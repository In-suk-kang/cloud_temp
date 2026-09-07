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
# VPC
# ============================================================

def collect_vpcs():

    vpcs = []

    paginator = ec2.get_paginator(
        "describe_vpcs"
    )

    for page in paginator.paginate():

        for vpc in page["Vpcs"]:

            vpcs.append({

                # Resource Anchor
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

                "tags": {
                    tag["Key"]: tag["Value"]
                    for tag in vpc.get(
                        "Tags", []
                    )
                }
            })

    return vpcs


# ============================================================
# Subnet
# ============================================================

def collect_subnets():

    subnets = []

    paginator = ec2.get_paginator(
        "describe_subnets"
    )

    for page in paginator.paginate():

        for subnet in page["Subnets"]:

            subnets.append({

                # Resource Anchor
                "subnet_id":
                    subnet["SubnetId"],

                "vpc_id":
                    subnet.get("VpcId"),

                "cidr_block":
                    subnet.get("CidrBlock"),

                "availability_zone":
                    subnet.get("AvailabilityZone"),

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

                "tags": {
                    tag["Key"]: tag["Value"]
                    for tag in subnet.get(
                        "Tags", []
                    )
                }
            })

    return subnets


# ============================================================
# Route Table
# ============================================================

def collect_route_tables():

    route_tables = []

    paginator = ec2.get_paginator(
        "describe_route_tables"
    )

    for page in paginator.paginate():

        for table in page["RouteTables"]:

            routes = []

            for route in table.get(
                "Routes", []
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

                    "destination_prefix_list":
                        route.get(
                            "DestinationPrefixListId"
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

                    "state":
                        route.get(
                            "State"
                        ),

                    "origin":
                        route.get(
                            "Origin"
                        )
                })

            associations = []

            for association in table.get(
                "Associations", []
            ):

                associations.append({

                    "route_table_association_id":
                        association.get(
                            "RouteTableAssociationId"
                        ),

                    "subnet_id":
                        association.get(
                            "SubnetId"
                        ),

                    "main":
                        association.get(
                            "Main"
                        ),

                    "association_state":
                        association.get(
                            "AssociationState"
                        )
                })

            route_tables.append({

                # Resource Anchor
                "route_table_id":
                    table["RouteTableId"],

                "vpc_id":
                    table.get("VpcId"),

                "routes":
                    routes,

                "associations":
                    associations,

                "tags": {
                    tag["Key"]: tag["Value"]
                    for tag in table.get(
                        "Tags", []
                    )
                }
            })

    return route_tables


# ============================================================
# Internet Gateway
# ============================================================

def collect_internet_gateways():

    gateways = []

    paginator = ec2.get_paginator(
        "describe_internet_gateways"
    )

    for page in paginator.paginate():

        for gateway in page[
            "InternetGateways"
        ]:

            attachments = []

            for attachment in gateway.get(
                "Attachments", []
            ):

                attachments.append({

                    "vpc_id":
                        attachment.get(
                            "VpcId"
                        ),

                    "state":
                        attachment.get(
                            "State"
                        )
                })

            gateways.append({

                # Resource Anchor
                "internet_gateway_id":
                    gateway[
                        "InternetGatewayId"
                    ],

                "attachments":
                    attachments,

                "tags": {
                    tag["Key"]: tag["Value"]
                    for tag in gateway.get(
                        "Tags", []
                    )
                }
            })

    return gateways


# ============================================================
# Network ACL
# ============================================================

def collect_network_acls():

    acls = []

    paginator = ec2.get_paginator(
        "describe_network_acls"
    )

    for page in paginator.paginate():

        for acl in page["NetworkAcls"]:

            entries = []

            for entry in acl.get(
                "Entries", []
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

                    "icmp_type_code":
                        entry.get(
                            "IcmpTypeCode"
                        ),

                    "port_range":
                        entry.get(
                            "PortRange"
                        )
                })

            associations = []

            for association in acl.get(
                "Associations", []
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

            acls.append({

                # Resource Anchor
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

                "tags": {
                    tag["Key"]: tag["Value"]
                    for tag in acl.get(
                        "Tags", []
                    )
                }
            })

    return acls


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
            "VPC",

        "resources": {

            "vpcs":
                collect_vpcs(),

            "subnets":
                collect_subnets(),

            "route_tables":
                collect_route_tables(),

            "internet_gateways":
                collect_internet_gateways(),

            "network_acls":
                collect_network_acls()
        }
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
        f"vpc_{timestamp}.json"
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
        f"[+] VPC snapshot saved: {filename}"
    )


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("VPC RESOURCE COLLECTION")
    print("=" * 60)

    snapshot = collect_snapshot()

    print(
        f"[+] VPCs: "
        f"{len(snapshot['resources']['vpcs'])}"
    )

    print(
        f"[+] Subnets: "
        f"{len(snapshot['resources']['subnets'])}"
    )

    print(
        f"[+] Route Tables: "
        f"{len(snapshot['resources']['route_tables'])}"
    )

    print(
        f"[+] Internet Gateways: "
        f"{len(snapshot['resources']['internet_gateways'])}"
    )

    print(
        f"[+] Network ACLs: "
        f"{len(snapshot['resources']['network_acls'])}"
    )

    save_snapshot(snapshot)

    print("[+] Collection complete")