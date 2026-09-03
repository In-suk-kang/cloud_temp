import boto3
import json
from botocore.exceptions import ClientError
from datetime import datetime
import os

class GeneralAWSDriftDetector:
    def __init__(self, region='ap-northeast-2'):
        self.ec2 = boto3.client('ec2', region_name=region)
        self.s3 = boto3.client('s3', region_name=region)
        self.iam = boto3.client('iam', region_name=region)
        self.ct = boto3.client('cloudtrail', region_name=region)
        self.kms = boto3.client('kms', region_name=region)
        self.sm = boto3.client('secretsmanager', region_name=region)

    def take_snapshot(self):
        snapshot = {
            'timestamp': datetime.now().isoformat(),
            'cloudtrail': {}, 'ec2': {}, 'security_group': {},
            'ebs_snapshot': {}, 'route_table': {},
            's3': {}, 'iam': {}, 'iam_access_key': {},
            'kms': {}, 'secretsmanager': {}
        }

        # 1. CloudTrail
        try:
            for trail in self.ct.describe_trails().get('trailList', []):
                name = trail['Name']
                status = self.ct.get_trail_status(Name=name)
                snapshot['cloudtrail'][name] = {'is_logging': status.get('IsLogging')}
        except ClientError: pass

        # 2. EC2, Security Group, EBS Snapshot, Route Table
        try:
            for r in self.ec2.describe_instances().get('Reservations', []):
                for i in r.get('Instances', []):
                    snapshot['ec2'][i['InstanceId']] = {'state': i['State']['Name']}
                    
            for sg in self.ec2.describe_security_groups().get('SecurityGroups', []):
                snapshot['security_group'][sg['GroupId']] = {
                    'group_name': sg.get('GroupName', ''),
                    'ingress': sg.get('IpPermissions', []),
                    'egress': sg.get('IpPermissionsEgress', [])
                }
                
            for snap in self.ec2.describe_snapshots(OwnerIds=['self']).get('Snapshots', []):
                snapshot['ebs_snapshot'][snap['SnapshotId']] = {
                    'volume_id': snap.get('VolumeId', ''),
                    'state': snap.get('State', '')
                }
                
            for rt in self.ec2.describe_route_tables().get('RouteTables', []):
                snapshot['route_table'][rt['RouteTableId']] = {
                    'vpc_id': rt.get('VpcId', ''),
                    'routes': rt.get('Routes', [])
                }
        except ClientError: pass

        # 3. S3
        try:
            for b in self.s3.list_buckets().get('Buckets', []):
                b_name = b['Name']
                b_info = {'creation_date': b['CreationDate'].isoformat()}
                try:
                    policy = self.s3.get_bucket_policy(Bucket=b_name)
                    b_info['policy'] = json.loads(policy['Policy'])
                except ClientError:
                    b_info['policy'] = None
                snapshot['s3'][b_name] = b_info
        except ClientError: pass

        # 4. IAM & Access Key
        try:
            for user in self.iam.list_users().get('Users', []):
                user_name = user['UserName']
                snapshot['iam'][f"User:{user_name}"] = {'created': user['CreateDate'].isoformat()}
                
                keys = self.iam.list_access_keys(UserName=user_name).get('AccessKeyMetadata', [])
                for key in keys:
                    snapshot['iam_access_key'][key['AccessKeyId']] = {
                        'user': user_name,
                        'status': key['Status']
                    }
                    
            for role in self.iam.list_roles().get('Roles', []):
                snapshot['iam'][f"Role:{role['RoleName']}"] = {'assume_role_policy': role.get('AssumeRolePolicyDocument')}
        except ClientError: pass

        # 5. KMS & Secrets Manager
        try:
            for key in self.kms.list_keys().get('Keys', []):
                meta = self.kms.describe_key(KeyId=key['KeyId']).get('KeyMetadata', {})
                snapshot['kms'][key['KeyId']] = {'state': meta.get('KeyState')}
            for secret in self.sm.list_secrets().get('SecretList', []):
                snapshot['secretsmanager'][secret['Name']] = {'arn': secret.get('ARN')}
        except ClientError: pass

        return snapshot

    def save_snapshot(self, snapshot, filename):
        os.makedirs("data", exist_ok=True)
        filepath = os.path.join("data", filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(snapshot, f, indent=2, ensure_ascii=False)

    def compare(self, before, after):
        drift = {'destroyed': [], 'modified': [], 'created': []}
        resource_types = [k for k in before.keys() if k != 'timestamp']

        for res_type in resource_types:
            before_res = before.get(res_type, {})
            after_res = after.get(res_type, {})

            for item_id, data in before_res.items():
                if item_id not in after_res:
                    drift['destroyed'].append({'type': res_type.upper(), 'id': item_id})
                elif after_res[item_id] != data:
                    drift['modified'].append({
                        'type': res_type.upper(), 'id': item_id, 'from': data, 'to': after_res[item_id]
                    })

            for item_id, data in after_res.items():
                if item_id not in before_res:
                    drift['created'].append({'type': res_type.upper(), 'id': item_id, 'state': data})

        return drift