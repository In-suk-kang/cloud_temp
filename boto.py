import boto3
import json
from datetime import datetime

class AWSDriftDetector:
    def __init__(self, region='ap-northeast-2'):
        # Boto3 Code Examples에 명시된 서비스 클라이언트 초기화
        self.ec2 = boto3.client('ec2', region_name=region)
        self.s3 = boto3.client('s3', region_name=region)
        self.sqs = boto3.resource('sqs', region_name=region)
        self.cw = boto3.client('cloudwatch', region_name=region)
        self.ddb = boto3.client('dynamodb', region_name=region)
        self.iam = boto3.client('iam', region_name=region) # IAM은 글로벌 서비스
        self.kms = boto3.client('kms', region_name=region)
        self.sm = boto3.client('secretsmanager', region_name=region)
        self.ses = boto3.client('ses', region_name=region)

    def take_snapshot(self):
        snapshot = {
            'timestamp': datetime.now().isoformat(),
            'ec2': {}, 's3': {}, 'sqs': {}, 'cloudwatch': {}, 
            'dynamodb': {}, 'iam': {}, 'kms': {}, 'secretsmanager': {}, 'ses': {}
        }

        # 1. EC2
        for r in self.ec2.describe_instances().get('Reservations', []):
            for i in r.get('Instances', []):
                snapshot['ec2'][i['InstanceId']] = {'state': i['State']['Name']}

        # 2. S3
        for b in self.s3.list_buckets().get('Buckets', []):
            snapshot['s3'][b['Name']] = {'creation_date': b['CreationDate'].isoformat()}

        # 3. SQS
        for queue in self.sqs.queues.all():
            snapshot['sqs'][queue.url] = {'DelaySeconds': queue.attributes.get('DelaySeconds')}

        # 4. CloudWatch (Alarms)
        for alarm in self.cw.describe_alarms().get('MetricAlarms', []):
            snapshot['cloudwatch'][alarm['AlarmName']] = {'state': alarm.get('StateValue')}

        # 5. DynamoDB (Tables)
        for table in self.ddb.list_tables().get('TableNames', []):
            snapshot['dynamodb'][table] = {'status': 'exists'}

        # 6. IAM (Users)
        for user in self.iam.list_users().get('Users', []):
            snapshot['iam'][user['UserName']] = {'created': user['CreateDate'].isoformat()}

        # 7. KMS (Keys)
        for key in self.kms.list_keys().get('Keys', []):
            snapshot['kms'][key['KeyId']] = {'arn': key['KeyArn']}

        # 8. Secrets Manager (Secrets)
        for secret in self.sm.list_secrets().get('SecretList', []):
            snapshot['secretsmanager'][secret['Name']] = {'arn': secret.get('ARN')}

        # 9. SES (Identities)
        for identity in self.ses.list_identities().get('Identities', []):
            snapshot['ses'][identity] = {'status': 'verified or pending'}

        return snapshot

    def save_snapshot(self, snapshot, filename):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(snapshot, f, indent=2, ensure_ascii=False)

    def compare(self, before, after):
        drift = {'destroyed': [], 'modified': [], 'created': []}
        
        # timestamp를 제외한 모든 서비스 항목을 동적으로 비교
        resource_types = [k for k in before.keys() if k != 'timestamp']

        for res_type in resource_types:
            before_res = before.get(res_type, {})
            after_res = after.get(res_type, {})

            # 삭제(Destroyed) 또는 수정(Modified) 감지
            for item_id, data in before_res.items():
                if item_id not in after_res:
                    drift['destroyed'].append({'type': res_type.upper(), 'id': item_id})
                elif after_res[item_id] != data:
                    drift['modified'].append({
                        'type': res_type.upper(), 
                        'id': item_id, 
                        'from': data, 
                        'to': after_res[item_id]
                    })

            # 생성(Created) 감지
            for item_id, data in after_res.items():
                if item_id not in before_res:
                    drift['created'].append({'type': res_type.upper(), 'id': item_id, 'state': data})

        return drift


if __name__ == "__main__":
    detector = AWSDriftDetector()

    # ==========================
    # 1. 공격 전 Snapshot
    # ==========================
    print("공격 전 다양한 AWS 서비스 상태 수집 중...")
    snap_before = detector.take_snapshot()
    detector.save_snapshot(snap_before, "snapshot_before.json")
    print("snapshot_before.json 저장 완료\n")

    # ==========================
    # 2. 공격 시뮬레이션 대기
    # ==========================
    input("공격 시뮬레이션 및 백도어 생성 등을 수행한 후 Enter를 누르세요...")

    # ==========================
    # 3. 공격 후 Snapshot
    # ==========================
    print("\n공격 후 AWS 상태 수집 중...")
    snap_after = detector.take_snapshot()
    detector.save_snapshot(snap_after, "snapshot_after.json")
    print("snapshot_after.json 저장 완료\n")

    # ==========================
    # 4. Drift 분석
    # ==========================
    drift_result = detector.compare(snap_before, snap_after)
    with open("drift_result.json", "w", encoding="utf-8") as f:
        json.dump(drift_result, f, indent=2, ensure_ascii=False)

    print("drift_result.json 저장 완료. 요약 결과:\n")
    print(json.dumps(drift_result, indent=2, ensure_ascii=False))