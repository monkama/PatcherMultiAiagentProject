import type { PipelineForm, Stage, StageState, StopStage } from './types';

export const stages: Stage[] = [
  {
    key: 'vuln',
    title: 'Vulnerability Collect',
    agent: 'vuln_collector_agent',
    description: 'CVE 데이터를 수집하고 후속 단계 payload를 생성합니다.',
    outputs: ['raw_result', 'risk_assessment_payload', 'operational_impact_payload'],
  },
  {
    key: 'asset',
    title: 'Asset Matching',
    agent: 'infra_matching_agent',
    description: '스택과 자산 정보를 조회해 취약점 영향 대상을 찾습니다.',
    outputs: ['infra_context'],
  },
  {
    key: 'risk',
    title: 'Risk Evaluation',
    agent: 'risk_evaluation_agent',
    description: '취약점과 자산 맥락을 결합해 위험도를 산정합니다.',
    outputs: ['risk_result'],
  },
  {
    key: 'patch',
    title: 'Patch Strategy',
    agent: 'patch_impact_agent',
    description: '위험도와 운영 영향을 기준으로 패치 전략을 판단합니다.',
    outputs: ['patch_strategy_result', 'asset_fact_trace'],
  },
  {
    key: 'patch_execution',
    title: 'Patch Execution',
    agent: 'patch_exec_agent',
    description: '선택된 조치를 실행하거나 실행 계획을 정리합니다.',
    outputs: ['patch_execution_result'],
  },
];

const stageOrder = stages.map((stage) => stage.key);

export const defaultForm: PipelineForm = {
  mode: 'full',
  stack_name: 'megathon',
  region: 'ap-northeast-2',
  cve_ids: 'CVE-2021-23017, CVE-2021-44228',
  stop_stage: '',
  allow_followup: true,
  infra_matching_runtime_arn: '',
  patch_impact_runtime_arn: '',
  patch_execution_runtime_arn: '',
  payloadJson: '{}',
};

export function getStageState(form: PipelineForm, key: StopStage): StageState {
  if (!key) return 'ready';
  const index = stageOrder.indexOf(key);
  const stopIndex = form.stop_stage ? stageOrder.indexOf(form.stop_stage) : -1;

  if (form.mode === 'vuln_only') return key === 'vuln' ? 'pending' : 'blocked';
  if (form.mode === 'asset_only') return key === 'asset' ? 'pending' : 'blocked';
  if (form.mode === 'risk_only') return key === 'risk' ? 'pending' : 'blocked';
  if (form.mode === 'patch_only') return key === 'patch' ? 'pending' : 'blocked';
  if (form.mode === 'patch_exec_only') return key === 'patch_execution' ? 'pending' : 'blocked';
  if (stopIndex >= 0) return index <= stopIndex ? 'pending' : 'blocked';
  return 'pending';
}

export function buildPayload(form: PipelineForm): Record<string, unknown> {
  const base: Record<string, unknown> = {
    mode: form.mode,
    stack_name: form.stack_name.trim() || 'megathon',
    region: form.region.trim() || 'ap-northeast-2',
    allow_followup: form.allow_followup,
  };

  const cveIds = form.cve_ids
    .split(',')
    .map((item) => item.trim().toUpperCase())
    .filter(Boolean);

  if (cveIds.length > 0) base.cve_ids = cveIds;
  if (form.stop_stage) base.stop_stage = form.stop_stage;
  if (form.infra_matching_runtime_arn.trim()) {
    base.infra_matching_runtime_arn = form.infra_matching_runtime_arn.trim();
  }
  if (form.patch_impact_runtime_arn.trim()) {
    base.patch_impact_runtime_arn = form.patch_impact_runtime_arn.trim();
  }
  if (form.patch_execution_runtime_arn.trim()) {
    base.patch_execution_runtime_arn = form.patch_execution_runtime_arn.trim();
  }

  const injected = parsePayloadJson(form.payloadJson);
  return { ...base, ...injected };
}

export function parsePayloadJson(value: string): Record<string, unknown> {
  const trimmed = value.trim();
  if (!trimmed || trimmed === '{}') return {};

  const parsed = JSON.parse(trimmed) as unknown;
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error('추가 payload는 JSON object여야 합니다.');
  }
  return parsed as Record<string, unknown>;
}

export function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}
