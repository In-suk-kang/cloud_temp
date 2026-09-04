import boto3
from src.detector import BaseCollector

class EC2Collector(BaseCollector):
    def __init__(self):
        super().__init__()
        self.ec2 = boto3.client('ec2')

    def discover_all(self):
        try:
            res = self.ec2.describe_instances()
            instances = []
            for r in res.get('Reservations', []):
                for inst in r.get('Instances', []):
                    instances.append(inst['InstanceId'])
            return instances
        except Exception:
            return []

    def get_state(self, instance_id):
        try:
            res = self.ec2.describe_instances(InstanceIds=[instance_id])
            inst = res['Reservations'][0]['Instances'][0]
            return {
                "InstanceId": instance_id,
                "State": inst.get('State', {}).get('Name'),
                "InstanceType": inst.get('InstanceType'),
                "SecurityGroups": [sg['GroupId'] for sg in inst.get('SecurityGroups', [])]
            }
        except Exception:
            return {}

    def collect_evidence(self, instance_id):
        evidence = []
        try:
            res = self.ec2.describe_instances(InstanceIds=[instance_id])
            inst = res['Reservations'][0]['Instances'][0]
            evidence.append({
                "source": "EC2_META", 
                "category": "COMPUTE_PLANE",
                "event_name": "InstanceLaunched",
                "event_time": str(inst.get('LaunchTime'))
            })
        except Exception:
            pass
        return evidence