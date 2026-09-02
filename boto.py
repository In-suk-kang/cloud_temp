import boto3
import json
from botocore.exceptions import ClientError
from datetime import datetime

class GeneralAWSDriftDetector:
    def __init__(self, region='ap-northeast-2'):
        # 범용 탐지를 위한 주요 서비스 클라이언트 초기화
        self.ec2 = boto3.client('ec2', region_name=region)
        self.s3 = boto3.client('s3', region_name=region)
        self.iam = boto3.client('iam', region_name=region)
        self.ct = boto3.client('cloudtrail', region_name=region)
        self.kms = boto3.client('kms', region_name=region)
        self.sm = boto3.client('secretsmanager', region_name=region)

    def take_snapshot(self):
        snapshot = {
            'timestamp': datetime.now().isoformat(),
            'cloudtrail': {}, 'ec2': {}, 's3': {}, 
            'iam': {}, 'kms': {}, 'secretsmanager': {}
        }

        # 1. CloudTrail (로깅 중단 감지)
        try:
            for trail in self.ct.describe_trails().get('trailList', []):
                name = trail['Name']
                status = self.ct.get_trail_status(Name=name)
                snapshot['cloudtrail'][name] = {'is_logging': status.get('IsLogging')}
        except ClientError: pass

        # 2. EC2 (인스턴스 및 보안 그룹 상태)
        try:
            for r in self.ec2.describe_instances().get('Reservations', []):
                for i in r.get('Instances', []):
                    snapshot['ec2'][f"Instance:{i['InstanceId']}"] = {'state': i['State']['Name']}
            for sg in self.ec2.describe_security_groups().get('SecurityGroups', []):
                snapshot['ec2'][f"SG:{sg['GroupId']}"] = {'ingress': sg.get('IpPermissions', [])}
        except ClientError: pass

        # 3. S3 (버킷 메타데이터 및 정책 백도어 감지)
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

        # 4. IAM (유저 생성 및 역할 신뢰 정책 변조 감지)
        try:
            for user in self.iam.list_users().get('Users', []):
                snapshot['iam'][f"User:{user['UserName']}"] = {'created': user['CreateDate'].isoformat()}
            for role in self.iam.list_roles().get('Roles', []):
                snapshot['iam'][f"Role:{role['RoleName']}"] = {'assume_role_policy': role.get('AssumeRolePolicyDocument')}
        except ClientError: pass

        # 5. KMS & Secrets Manager (데이터 파괴 및 탈취 감지)
        try:
            for key in self.kms.list_keys().get('Keys', []):
                meta = self.kms.describe_key(KeyId=key['KeyId']).get('KeyMetadata', {})
                snapshot['kms'][key['KeyId']] = {'state': meta.get('KeyState')}
            for secret in self.sm.list_secrets().get('SecretList', []):
                snapshot['secretsmanager'][secret['Name']] = {'arn': secret.get('ARN')}
        except ClientError: pass

        return snapshot

    def save_snapshot(self, snapshot, filename):
        with open(filename, 'w', encoding='utf-8') as f:
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

if __name__ == "__main__":
    # 수정 포인트: 클래스 이름과 일치하도록 GeneralAWSDriftDetector 사용
    detector = GeneralAWSDriftDetector()

    # ==========================
    # 1. 공격 전 Snapshot
    # ==========================
    print("[1] 공격 전 AWS 상태 수집 중...")
    snap_before = detector.take_snapshot()
    detector.save_snapshot(snap_before, "snapshot_before.json")
    print("snapshot_before.json 저장 완료\n")

    # ==========================
    # 2. 콘솔에서 공격 시뮬레이션 대기
    # ==========================
    input("터미널 콘솔에서 Stratus Red Team 공격을 수행한 후 Enter를 누르세요...")

    # ==========================
    # 3. 공격 후 Snapshot
    # ==========================
    print("\n[2] 공격 후 AWS 상태 수집 중...")
    snap_after = detector.take_snapshot()
    detector.save_snapshot(snap_after, "snapshot_after.json")
    print("snapshot_after.json 저장 완료\n")

    # ==========================
    # 4. Drift 분석 및 결과 저장
    # ==========================
    print("[3] 범용 Drift 분석 수행 중...")
    drift_result = detector.compare(snap_before, snap_after)
    
    with open("drift_result.json", "w", encoding="utf-8") as f:
        json.dump(drift_result, f, indent=2, ensure_ascii=False)

    print("drift_result.json 저장 완료. 요약 결과:\n")
    print(json.dumps(drift_result, indent=2, ensure_ascii=False))