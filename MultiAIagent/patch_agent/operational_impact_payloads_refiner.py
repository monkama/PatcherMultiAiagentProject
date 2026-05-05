import json
import os
from typing import List, Dict

class OperationalRefiner(list):
    def __init__(self, file_path: str = 'operational_impact_payloads.json'):
        super().__init__()
        base_dir = os.path.dirname(os.path.abspath(__file__))
        full_path = os.path.join(base_dir, file_path)

        if os.path.exists(full_path):
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    impact_json = json.load(f)
                
                # 핵심 데이터 추출 로직 실행
                records = impact_json.get("records", [])
                for record in records:
                    core_info = {
                        "cve_id": record.get("cve_id"),
                        "title": record.get("title"), # 취약점 명칭 추가
                        "product_name": record.get("product_name"),
                        "patch_type": record.get("patch_type"),
                        "affected_versions": record.get("affected_version_range", []),
                        "target_fixed_version": record.get("fixed_version"),
                        "operational_impacts": record.get("operational_impacts", []), # 전체 영향도 유지
                        "security_domain": record.get("security_domain"), # 보안 영역 추가
                        "notes": record.get("notes") # 상세 설명(핵심) 유지
                    }
                    self.append(core_info)
            except Exception as e:
                print(f"OperationalRefiner Error: {e}")