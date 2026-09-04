import dictdiffer
import boto3

class DiffEngine:
    def extract_changes(self, old_snapshot, new_snapshot):
        changes = list(dictdiffer.diff(old_snapshot, new_snapshot))
        parsed_diffs = []
        
        for change_type, path, values in changes:
            base_path = path if isinstance(path, str) else ".".join(map(str, path))
            
            if change_type == 'change':
                old_val, new_val = values
                parsed_diffs.append({
                    "change_type": change_type,
                    "json_path": base_path,
                    "before_val": str(old_val),
                    "after_val": str(new_val)
                })
            
            elif change_type in ['add', 'remove']:
                for key, val in values:
                    full_path = f"{base_path}.{key}" if base_path else str(key)
                    parsed_diffs.append({
                        "change_type": change_type,
                        "json_path": full_path,
                        "before_val": "NONE" if change_type == 'add' else str(val),
                        "after_val": str(val) if change_type == 'add' else "NONE"
                    })
                    
        return parsed_diffs

class BaseCollector:
    def __init__(self):
        self.ct = boto3.client('cloudtrail')

    def collect_immutable_trail(self, resource_name):
        try:
            events = self.ct.lookup_events(
                LookupAttributes=[{'AttributeKey': 'ResourceName', 'AttributeValue': resource_name}],
                MaxResults=3
            )
            return [{
                "source": "IMMUTABLE_TRAIL", 
                "category": "CONTROL_PLANE",
                "event_name": e['EventName'],
                "event_time": str(e['EventTime'])
            } for e in events.get('Events', [])]
        except Exception:
            return []