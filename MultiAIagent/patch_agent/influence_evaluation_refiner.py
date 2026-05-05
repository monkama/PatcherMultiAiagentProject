import json
import os

class InfluenceRefiner(list):
    def __init__(self, file_path: str = 'influence_evaluation.json'):
        super().__init__()
        base_dir = os.path.dirname(os.path.abspath(__file__))
        full_path = os.path.join(base_dir, file_path)

        if os.path.exists(full_path):
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    influence_json = json.load(f)
                
                for item in influence_json:
                    # action_plan이 삭제되었으므로, cve_id가 "None"이 아닌 실제 취약점 대상만 필터링합니다.
                    if item.get('cve_id') != 'None':
                        res = item.get('assessment_result', {})
                        
                        core_info = {
                            "instance_id": item.get("instance_id"),
                            "cve_id": item.get("cve_id"),
                            "impact_level": res.get("impact_level"),
                            "estimated_downtime": res.get("estimated_downtime"),
                            "os_reboot_required": res.get("os_reboot_required"),
                            "data_loss_risk": res.get("data_loss_risk"),
                            "rollback_complexity": res.get("rollback_complexity"),
                            "config_overwrite_risk": res.get("config_overwrite_risk"),
                            "requires_rolling_update": res.get("requires_rolling_update"),
                            "maintenance_window_only": res.get("maintenance_window_only")
                        }
                        self.append(core_info)
            except Exception as e:
                print(f"InfluenceRefiner Error: {e}")