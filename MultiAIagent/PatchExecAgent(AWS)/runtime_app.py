from __future__ import annotations
from bedrock_agentcore.runtime import BedrockAgentCoreApp
# 알맹이 폴더의 main.py에서 실행 함수를 가져옵니다.
from patch_exec_agent.main import execute_patch_logic

app = BedrockAgentCoreApp()

@app.entrypoint
def invoke(payload: dict | None) -> str:
    payload = payload or {}
    # 요청을 받아서 진짜 일꾼(execute_patch_logic)에게 넘깁니다.
    result = execute_patch_logic(payload)
    return result

if __name__ == "__main__":
    app.run()