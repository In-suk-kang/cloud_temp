import dictdiffer
import boto3

class DiffEngine:
    def extract_changes(self, old_snapshot, new_snapshot):
        changes = list(dictdiffer.diff(old_snapshot, new_snapshot))
        parsed_diffs = []
        for change_type, path, values in changes:
            parsed_diffs.append({
                "change_type": change_type,
                "json_path": path if isinstance(path, str) else ".".join(map(str, path)),
                "details": str(values)
            })
        return parsed_diffs

class BaseCollector:
    def __init__(self):
        self.ct = boto3.client('cloudtrail')

    def collect_immutable_trail(self, resource_name):
        """CloudTrail 90일 기본 이벤트 히스토리 (공통 보강 증거)"""
        try:
            events = self.ct.lookup_events(
                LookupAttributes=[{'AttributeKey': 'ResourceName', 'AttributeValue': resource_name}],
                MaxResults=3
            )
            return [{
                "source": "IMMUTABLE_TRAIL", 
                "category": "CONTROL_PLANE",
                "data": f"Event: {e['EventName']} at {e['EventTime']}"
            } for e in events.get('Events', [])]
        except Exception:
            return []