import boto3
import json
from src.detector import BaseCollector

class S3Collector(BaseCollector):
    def __init__(self):
        super().__init__()
        self.s3 = boto3.client('s3')

    def discover_all(self):
        try:
            res = self.s3.list_buckets()
            return [b['Name'] for b in res.get('Buckets', [])]
        except Exception:
            return []

    def get_state(self, bucket_name):
        state = {"BucketName": bucket_name}
        try:
            res_pub = self.s3.get_public_access_block(Bucket=bucket_name)
            state["PublicAccessBlockConfiguration"] = res_pub['PublicAccessBlockConfiguration']
        except Exception:
            state["PublicAccessBlockConfiguration"] = None

        try:
            res_pol = self.s3.get_bucket_policy(Bucket=bucket_name)
            state["BucketPolicy"] = json.loads(res_pol['Policy'])
        except Exception:
            state["BucketPolicy"] = None
        return state

    def collect_evidence(self, bucket_name):
        evidence = []
        try:
            objs = self.s3.list_objects_v2(Bucket=bucket_name, MaxKeys=5)
            if 'Contents' in objs:
                latest = max(objs['Contents'], key=lambda x: x['LastModified'])
                evidence.append({
                    "source": "S3_OBJECT", "category": "DATA_PLANE",
                    "data": f"Latest Object Modified: {latest['LastModified']}"
                })
        except Exception:
            pass
        return evidence