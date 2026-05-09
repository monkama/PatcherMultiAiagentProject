import json
import os
from typing import List, Dict, Optional, Union

DEFAULT_INPUT_PATH = "infra_context.json"


class AssetRiskAnalyzer:
    def __init__(self, asset_data: Dict):
        self.data = asset_data
        self.assets = asset_data.get("assets", [])

    def extract_critical_assets(self) -> List[Dict]:
        """자산 데이터를 후보 식별용 최소 요약으로 정제한다.

        public exposure, root process 같은 런타임 위험 조건은 risk agent 가
        query_asset_details 도구로 직접 확인하도록 프롬프트 입력에서 숨긴다.
        """
        refined_assets = []

        for asset in self.assets:
            metadata = asset.get("metadata", {})

            software_list = [
                {
                    "product": sw.get("product"),
                    "version": sw.get("version"),
                    "cpe": sw.get("cpe"),
                }
                for sw in asset.get("installed_software", [])
            ]

            refined_assets.append({
                "asset_id": asset.get("asset_id"),
                "hostname": asset.get("hostname"),
                "tier": asset.get("tier"),
                "private_ip": asset.get("private_ip"),
                "vulnerable_software": software_list,
                "os_info": asset.get("os_info", {}),
                "business_criticality": metadata.get("business_criticality", "unknown"),
            })

        return refined_assets


def get_refined_asset_report(source: Optional[Union[dict, str]] = None):
    """infra_context 정제.

    source:
        - dict 직접 전달 (AgentCore Runtime 호출 시 권장)
        - str 경로 전달 (로컬 테스트용)
        - None — 기본 경로 'infra_context.json' 읽음
    """
    if source is None:
        source = DEFAULT_INPUT_PATH

    if isinstance(source, str):
        if not os.path.exists(source):
            print(f"경고: {source} 파일을 찾을 수 없습니다.")
            return []
        try:
            with open(source, "r", encoding="utf-8") as f:
                asset_json = json.load(f)
        except Exception as e:
            print(f"파일 로드 실패: {e}")
            return []
    elif isinstance(source, dict):
        asset_json = source
    else:
        print(f"지원하지 않는 source 타입: {type(source)}")
        return []

    try:
        analyzer = AssetRiskAnalyzer(asset_json)
        return analyzer.extract_critical_assets()
    except Exception as e:
        print(f"데이터 정제 중 예외 발생: {e}")
        return []


if __name__ == "__main__":
    print("--- 인프라 데이터 정제 테스트 시작 ---")
    test_results = get_refined_asset_report()
    for res in test_results[:2]:
        print(f"ID: {res['asset_id']} | Tier: {res['tier']} | Software: {res['vulnerable_software']}")
