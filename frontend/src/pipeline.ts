import type { AgentDataFlow, DataFile, PipelineForm, Stage, StageState, StopStage } from './types';

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
const emptyValue = '(not available)';

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

export function buildAgentDataFlows(result: unknown): AgentDataFlow[] {
  const root = asRecord(result);
  if (!root) return [];

  const latestBundle = parseLatestBundle(root);
  if (latestBundle) return buildLatestFileFlows(latestBundle);

  const vulnStage = asRecord(root.vuln_stage);
  const assetStage = asRecord(root.asset_stage);
  const riskStage = asRecord(root.risk_stage);
  const patchStage = asRecord(root.patch_stage);
  const patchExecutionStage = asRecord(root.patch_execution_stage);

  const infraContext = pickFirst(
    readRecord(assetStage, 'result'),
    readRecord(root, 'infra_context'),
  );
  const riskResult = pickFirst(
    riskStage?.result,
    root.risk_result,
  );
  const patchStrategyResult = pickFirst(
    readRecord(patchStage, 'result'),
    readRecord(root, 'patch_strategy_result'),
    root.patch_result,
  );

  return [
    {
      key: 'vuln',
      title: 'Vulnerability Collect',
      agent: 'vuln_collector_agent',
      status: readText(vulnStage, 'status'),
      received: recordAsDataFiles('response.json reconstructed input', 'MultiAIagent/OchestraResult/orchestrator_agent/latest/response.json', compactRecord({
        mode: root.mode,
        stack_name: root.stack_name,
        region: root.region,
        cve_ids: pickFirst(vulnStage?.cve_ids, root.cve_ids),
      })),
      produced: recordAsDataFiles('response.json vuln_stage', 'MultiAIagent/OchestraResult/orchestrator_agent/latest/response.json', compactRecord({
        raw_result: vulnStage?.raw_result,
        risk_assessment_payload: vulnStage?.risk_assessment_payload,
        operational_impact_payload: vulnStage?.operational_impact_payload,
        asset_matching_payload: vulnStage?.asset_matching_payload,
      })),
    },
    {
      key: 'asset',
      title: 'Asset Matching',
      agent: 'infra_matching_agent',
      status: readText(assetStage, 'status'),
      received: recordAsDataFiles('response.json reconstructed input', 'MultiAIagent/OchestraResult/orchestrator_agent/latest/response.json', compactRecord({
        stack_name: root.stack_name,
        region: root.region,
        asset_matching_payload: vulnStage?.asset_matching_payload,
      })),
      produced: recordAsDataFiles('response.json asset_stage', 'MultiAIagent/OchestraResult/orchestrator_agent/latest/response.json', compactRecord({
        infra_context: infraContext,
        output_path: assetStage?.output_path,
      })),
    },
    {
      key: 'risk',
      title: 'Risk Evaluation',
      agent: 'risk_evaluation_agent',
      status: readText(riskStage, 'status'),
      received: recordAsDataFiles('response.json reconstructed input', 'MultiAIagent/OchestraResult/orchestrator_agent/latest/response.json', compactRecord({
        region: root.region,
        infra_context: infraContext,
        risk_assessment_payload: vulnStage?.risk_assessment_payload,
      })),
      produced: recordAsDataFiles('response.json risk_stage', 'MultiAIagent/OchestraResult/orchestrator_agent/latest/response.json', compactRecord({
        risk_result: riskResult,
        record_count: riskStage?.record_count,
        swarm_queries: riskStage?.swarm_queries,
      })),
    },
    {
      key: 'patch',
      title: 'Patch Strategy',
      agent: 'patch_impact_agent',
      status: readText(patchStage, 'status'),
      received: recordAsDataFiles('response.json reconstructed input', 'MultiAIagent/OchestraResult/orchestrator_agent/latest/response.json', compactRecord({
        region: root.region,
        infra_context: infraContext,
        risk_result: riskResult,
        operational_payload: vulnStage?.operational_impact_payload,
      })),
      produced: recordAsDataFiles('response.json patch_stage', 'MultiAIagent/OchestraResult/orchestrator_agent/latest/response.json', compactRecord({
        patch_strategy_result: patchStrategyResult,
        strategy_context: patchStage?.strategy_context,
        asset_fact_trace: patchStage?.asset_fact_trace,
      })),
    },
    {
      key: 'patch_execution',
      title: 'Patch Execution',
      agent: 'patch_exec_agent',
      status: readText(patchExecutionStage, 'status'),
      received: recordAsDataFiles('response.json reconstructed input', 'MultiAIagent/OchestraResult/orchestrator_agent/latest/response.json', compactRecord({
        region: root.region,
        patch_strategy_result: patchStrategyResult,
      })),
      produced: recordAsDataFiles('response.json patch_execution_stage', 'MultiAIagent/OchestraResult/orchestrator_agent/latest/response.json', compactRecord({
        patch_execution_result: patchExecutionStage?.result,
        result_path: patchExecutionStage?.result_path,
      })),
    },
  ];
}

type LatestBundle = {
  agents: Record<string, LatestAgent>;
};

type LatestAgent = {
  latestPath: string;
  files: Record<string, DataFile>;
};

function parseLatestBundle(root: Record<string, unknown>): LatestBundle | null {
  const agents = asRecord(root.agents);
  if (!agents) return null;

  const parsedAgents: Record<string, LatestAgent> = {};

  for (const [agentName, rawAgent] of Object.entries(agents)) {
    const agent = asRecord(rawAgent);
    const rawFiles = asRecord(agent?.files);
    const files: Record<string, DataFile> = {};

    if (rawFiles) {
      for (const [filename, rawFile] of Object.entries(rawFiles)) {
        const file = asRecord(rawFile);
        const path = typeof file?.path === 'string'
          ? file.path
          : `MultiAIagent/OchestraResult/${agentName}/latest/${filename}`;

        files[filename] = {
          label: filename,
          path,
          value: file && 'value' in file ? file.value : rawFile,
        };
      }
    }

    parsedAgents[agentName] = {
      latestPath: typeof agent?.latest_path === 'string'
        ? agent.latest_path
        : `MultiAIagent/OchestraResult/${agentName}/latest`,
      files,
    };
  }

  return { agents: parsedAgents };
}

function buildLatestFileFlows(bundle: LatestBundle): AgentDataFlow[] {
  const summary = readFileValue(bundle, 'orchestrator_agent', 'summary.json');
  const summaryRecord = asRecord(summary);
  const savedAgentDirs = asRecord(summaryRecord?.saved_agent_dirs);
  const pipeline = Array.isArray(summaryRecord?.pipeline) ? summaryRecord.pipeline.map(String) : [];

  const hasRun = (folderName: string, pipelineName: string) => {
    const savedPath = savedAgentDirs?.[folderName];
    return Boolean(savedPath) || pipeline.includes(pipelineName);
  };

  const vulnRan = hasRun('vuln_collector_agent', 'vuln_collector_agent');
  const assetRan = hasRun('asset_matching_agent', 'infra_matching_agent');
  const riskRan = hasRun('risk_evaluation_agent', 'risk_evaluation_agent');
  const patchRan = hasRun('patch_impact_agent', 'patch_impact_agent');
  const patchExecutionRan = hasRun('patch_execution_agent', 'patch_execution_agent');

  return [
    {
      key: 'vuln',
      title: 'Vulnerability Collect',
      agent: 'vuln_collector_agent',
      status: statusFromFiles(bundle, 'vuln_collector_agent', vulnRan),
      received: files(bundle, 'orchestrator_agent', ['request_payload.json']),
      produced: ownFiles(bundle, 'vuln_collector_agent', vulnRan),
    },
    {
      key: 'asset',
      title: 'Asset Matching',
      agent: 'infra_matching_agent',
      status: statusFromFiles(bundle, 'asset_matching_agent', assetRan),
      received: files(bundle, 'vuln_collector_agent', ['asset_matching_payload.json']),
      produced: ownFiles(bundle, 'asset_matching_agent', assetRan),
    },
    {
      key: 'risk',
      title: 'Risk Evaluation',
      agent: 'risk_evaluation_agent',
      status: statusFromFiles(bundle, 'risk_evaluation_agent', riskRan),
      received: [
        ...files(bundle, 'asset_matching_agent', ['infra_context.json']),
        ...files(bundle, 'vuln_collector_agent', ['risk_assessment_payloads.json']),
      ],
      produced: ownFiles(bundle, 'risk_evaluation_agent', riskRan),
    },
    {
      key: 'patch',
      title: 'Patch Strategy',
      agent: 'patch_impact_agent',
      status: statusFromFiles(bundle, 'patch_impact_agent', patchRan),
      received: [
        ...files(bundle, 'asset_matching_agent', ['infra_context.json']),
        ...files(bundle, 'risk_evaluation_agent', ['risk_evaluation_result.json']),
        ...files(bundle, 'vuln_collector_agent', ['operational_impact_payloads.json']),
      ],
      produced: ownFiles(bundle, 'patch_impact_agent', patchRan),
    },
    {
      key: 'patch_execution',
      title: 'Patch Execution',
      agent: 'patch_exec_agent',
      status: statusFromFiles(bundle, 'patch_execution_agent', patchExecutionRan),
      received: files(bundle, 'patch_impact_agent', ['patch_strategy_result.json']),
      produced: ownFiles(bundle, 'patch_execution_agent', patchExecutionRan),
    },
  ];
}

function files(bundle: LatestBundle, agentName: string, filenames: string[]): DataFile[] {
  const agent = bundle.agents[agentName];
  if (!agent) return [];

  return filenames
    .map((filename) => agent.files[filename])
    .filter((file): file is DataFile => Boolean(file));
}

function ownFiles(bundle: LatestBundle, agentName: string, enabled: boolean): DataFile[] {
  if (!enabled) return [];

  const agent = bundle.agents[agentName];
  if (!agent) return [];

  return Object.values(agent.files).sort((left, right) => left.label.localeCompare(right.label));
}

function readFileValue(bundle: LatestBundle, agentName: string, filename: string): unknown {
  return bundle.agents[agentName]?.files[filename]?.value;
}

function statusFromFiles(bundle: LatestBundle, agentName: string, enabled: boolean): string {
  if (!enabled) return 'not-run';

  const stageResponse = asRecord(readFileValue(bundle, agentName, 'stage_response.json'));
  const status = stageResponse?.status;
  if (typeof status === 'string' && status.trim()) return status;

  return Object.keys(bundle.agents[agentName]?.files ?? {}).length > 0 ? 'ok' : 'missing';
}

export function summarizePipelineResult(result: unknown): Array<{ label: string; value: string }> {
  const root = asRecord(result);
  if (!root) {
    return [
      { label: 'Mode', value: '-' },
      { label: 'Pipeline', value: '-' },
      { label: 'Status', value: '대기' },
    ];
  }

  const latestBundle = parseLatestBundle(root);
  if (latestBundle) {
    const summary = asRecord(readFileValue(latestBundle, 'orchestrator_agent', 'summary.json'));
    const pipeline = Array.isArray(summary?.pipeline) ? summary.pipeline : [];

    return [
      { label: 'Mode', value: String(summary?.mode || '-') },
      { label: 'Pipeline', value: pipeline.length ? `${pipeline.length} stages` : '-' },
      { label: 'Status', value: String(summary?.agent_message || '분석 대기') },
    ];
  }

  const pipeline = Array.isArray(root.pipeline) ? root.pipeline : [];
  return [
    { label: 'Mode', value: String(root.mode || '-') },
    { label: 'Pipeline', value: pipeline.length ? `${pipeline.length} stages` : '-' },
    { label: 'Status', value: String(root.agent_message || '분석됨') },
  ];
}

export function formatDataBlock(value: Record<string, unknown>): string {
  return Object.keys(value).length > 0 ? prettyJson(value) : emptyValue;
}

export function formatUnknownDataBlock(value: unknown): string {
  return hasValue(value) ? prettyJson(value) : emptyValue;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function readRecord(value: Record<string, unknown> | null | undefined, key: string): Record<string, unknown> | null {
  return value ? asRecord(value[key]) : null;
}

function readText(value: Record<string, unknown> | null | undefined, key: string): string {
  const raw = value?.[key];
  return typeof raw === 'string' && raw.trim() ? raw : 'not-run';
}

function pickFirst(...values: unknown[]): unknown {
  return values.find((value) => hasValue(value));
}

function compactRecord(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(value).filter(([, entry]) => hasValue(entry)),
  );
}

function recordAsDataFiles(label: string, path: string, value: Record<string, unknown>): DataFile[] {
  return Object.keys(value).length > 0
    ? [{ label, path, value }]
    : [];
}

function hasValue(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string') return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'object') return Object.keys(value).length > 0;
  return true;
}
