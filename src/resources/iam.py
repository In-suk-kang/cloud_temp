import boto3
from src.detector import BaseCollector

class IAMCollector(BaseCollector):
    def __init__(self):
        super().__init__()
        self.iam = boto3.client('iam')

    def discover_all(self):
        try:
            res = self.iam.list_roles()
            return [r['RoleName'] for r in res.get('Roles', [])]
        except Exception:
            return []

    def get_state(self, role_name):
        try:
            res = self.iam.get_role(RoleName=role_name)
            role = res['Role']
            return {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": role.get('AssumeRolePolicyDocument'),
                "Path": role.get('Path')
            }
        except Exception:
            return {}

    def collect_evidence(self, role_name):
        evidence = []
        try:
            res = self.iam.get_role(RoleName=role_name)
            create_date = res['Role'].get('CreateDate')
            evidence.append({
                "source": "IAM_META", "category": "CONTROL_PLANE",
                "data": f"Role CreateDate: {str(create_date)}"
            })
        except Exception:
            pass
        return evidence