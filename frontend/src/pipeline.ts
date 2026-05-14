import type { AgentDataFlow, DataFile, PipelineForm, Stage, StageState, StopStage, TimelineStep } from './types';

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

export function summarizeUserResult(result: unknown): Array<{ label: string; value: string }> {
  const root = asRecord(result);
  const latestBundle = root ? parseLatestBundle(root) : null;
  if (!latestBundle) return summarizePipelineResult(result);

  const summary = asRecord(readFileValue(latestBundle, 'orchestrator_agent', 'summary.json'));
  const pipeline = Array.isArray(summary?.pipeline) ? summary.pipeline : [];
  const riskResults = arrayOfRecords(readFileValue(latestBundle, 'risk_evaluation_agent', 'risk_evaluation_result.json'));
  const patchResult = asRecord(readFileValue(latestBundle, 'patch_impact_agent', 'patch_strategy_result.json'));
  const patchRecords = arrayOfRecords(patchResult?.records);
  const cveIds = new Set([
    ...riskResults.map((record) => String(record.cve_id || '')).filter(Boolean),
    ...patchRecords.map((record) => String(record.cve_id || '')).filter(Boolean),
  ]);

  return [
    { label: '실행 모드', value: String(summary?.mode || '-') },
    { label: '진행 단계', value: pipeline.length ? `${pipeline.length}개 에이전트 완료` : '-' },
    { label: '취약점', value: cveIds.size ? `${cveIds.size}건 분석` : '-' },
    { label: '영향 자산', value: `${collectImpactedAssets(riskResults).length}개` },
    { label: '권장 조치', value: summarizeActions(patchRecords) },
  ];
}

export function buildResultTimeline(result: unknown): TimelineStep[] {
  const root = asRecord(result);
  if (!root) return [];

  const latestBundle = parseLatestBundle(root);
  if (!latestBundle) return buildResponseTimeline(root);

  const summary = asRecord(readFileValue(latestBundle, 'orchestrator_agent', 'summary.json'));
  const savedAgentDirs = asRecord(summary?.saved_agent_dirs);
  const pipeline = Array.isArray(summary?.pipeline) ? summary.pipeline.map(String) : [];
  const hasRun = (folderName: string, pipelineName: string) => Boolean(savedAgentDirs?.[folderName]) || pipeline.includes(pipelineName);

  const vulnRecords = arrayOfRecords(asRecord(readFileValue(latestBundle, 'vuln_collector_agent', 'risk_assessment_payloads.json'))?.records);
  const operationalRecords = arrayOfRecords(asRecord(readFileValue(latestBundle, 'vuln_collector_agent', 'operational_impact_payloads.json'))?.records);
  const infraContext = asRecord(readFileValue(latestBundle, 'asset_matching_agent', 'infra_context.json'));
  const assets = arrayOfRecords(infraContext?.assets);
  const riskResults = arrayOfRecords(readFileValue(latestBundle, 'risk_evaluation_agent', 'risk_evaluation_result.json'));
  const patchResult = asRecord(readFileValue(latestBundle, 'patch_impact_agent', 'patch_strategy_result.json'));
  const patchRecords = arrayOfRecords(patchResult?.records);
  const impactedAssets = collectImpactedAssets(riskResults);
  const patchExecutionRan = hasRun('patch_execution_agent', 'patch_execution_agent');

  return [
    {
      key: 'vuln',
      title: '취약점 수집 에이전트',
      agent: 'vuln_collector_agent',
      status: statusFromFiles(latestBundle, 'vuln_collector_agent', hasRun('vuln_collector_agent', 'vuln_collector_agent')),
      received: ['오케스트레이터의 실행 요청과 분석 대상 CVE 목록을 기준으로 취약점 정보를 정리했습니다.'],
      reasoning: [
        vulnRecords.length
          ? `${vulnRecords.map((record) => record.cve_id).filter(Boolean).join(', ')}를 후속 에이전트가 사용할 수 있는 기준 정보로 변환했습니다.`
          : '취약점 기준 정보가 아직 충분히 생성되지 않았습니다.',
        '각 CVE에 대해 영향 대상, 악용 조건, 자산에서 확인해야 할 체크리스트를 분리했습니다.',
      ],
      result: [
        vulnRecords.length
          ? `${vulnRecords.length}건의 취약점 기준 payload와 운영 영향 payload가 생성되었습니다.`
          : '취약점 분석 결과가 비어 있어 다음 단계에서 사용할 근거가 제한됩니다.',
        firstText(vulnRecords, 'affected', '영향받는 제품과 버전 범위를 정리했습니다.'),
        firstText(operationalRecords, 'primary_remediation', '패치 또는 완화 조치의 운영상 고려사항을 정리했습니다.'),
        '이 결과는 자산 매칭, 위험 평가, 패치 전략 단계가 각각 필요한 관점으로 나누어 사용합니다.',
      ],
      handoff: 'asset_matching_payload.json, risk_assessment_payloads.json, operational_impact_payloads.json을 다음 단계에 제공합니다.',
      highlights: [
        { label: 'CVE', value: vulnRecords.length ? `${vulnRecords.length}건` : '-' },
        { label: '운영 영향', value: operationalRecords.length ? `${operationalRecords.length}건` : '-' },
      ],
    },
    {
      key: 'asset',
      title: '자산 매칭 에이전트',
      agent: 'infra_matching_agent',
      status: statusFromFiles(latestBundle, 'asset_matching_agent', hasRun('asset_matching_agent', 'infra_matching_agent')),
      received: ['취약점 수집 에이전트가 만든 asset_matching_payload.json을 받아 실제 인프라 자산과 대조했습니다.'],
      reasoning: [
        `${assets.length}개 자산의 OS, 설치 소프트웨어, 네트워크 노출, 보안 컨텍스트를 확인했습니다.`,
        componentSummary(assets),
        '인터넷 노출 여부와 listening port를 함께 보면서 취약점이 실제 서비스에 닿을 가능성을 추정했습니다.',
      ],
      result: [
        `${publicAssetCount(assets)}개 자산은 public IP 또는 인터넷 노출 신호가 있어 우선 검토 대상으로 볼 수 있습니다.`,
        'nginx와 log4j처럼 CVE와 직접 연결될 수 있는 컴포넌트를 자산별로 식별했습니다.',
        '자산 간 reachability 정보도 함께 정리해 web, app, db 계층의 연결 흐름을 확인할 수 있게 했습니다.',
        '이 자산 맥락은 위험 평가 에이전트가 CVE별 실제 영향도를 계산하는 근거가 됩니다.',
      ],
      handoff: 'infra_context.json을 위험 평가와 패치 전략 에이전트에 전달합니다.',
      highlights: [
        { label: '자산', value: `${assets.length}개` },
        { label: '인터넷 노출', value: `${publicAssetCount(assets)}개` },
      ],
    },
    {
      key: 'risk',
      title: '위험 평가 에이전트',
      agent: 'risk_evaluation_agent',
      status: statusFromFiles(latestBundle, 'risk_evaluation_agent', hasRun('risk_evaluation_agent', 'risk_evaluation_agent')),
      received: ['infra_context.json과 risk_assessment_payloads.json을 함께 받아 취약점 기준 정보와 실제 자산 상태를 결합했습니다.'],
      reasoning: [
        riskResults.length
          ? `${riskResults.length}건의 CVE에 대해 영향받는 자산과 위험도 조정 이유를 계산했습니다.`
          : '위험 평가 결과가 아직 생성되지 않았습니다.',
        firstImpactedReason(riskResults),
        '확인되지 않은 런타임 상태는 안전하다고 가정하지 않고, 필요한 경우 위험도를 보수적으로 유지했습니다.',
      ],
      result: [
        impactedAssets.length
          ? `${impactedAssets.length}개 자산이 실제 영향 가능 대상으로 분류되었습니다.`
          : '현재 결과에서 영향 자산은 확인되지 않았습니다.',
        riskLevelSummary(riskResults),
        firstRemediation(riskResults),
        '이 위험 평가 결과는 패치 전략 에이전트가 자동 조치, 수동 검토, 임시 완화 중 무엇이 적절한지 판단하는 기준이 됩니다.',
      ],
      handoff: 'risk_evaluation_result.json을 패치 전략 에이전트에 전달합니다.',
      highlights: [
        { label: '영향 자산', value: `${impactedAssets.length}개` },
        { label: '위험도', value: dominantRiskLevel(riskResults) },
      ],
    },
    {
      key: 'patch',
      title: '패치 전략 에이전트',
      agent: 'patch_impact_agent',
      status: statusFromFiles(latestBundle, 'patch_impact_agent', hasRun('patch_impact_agent', 'patch_impact_agent')),
      received: ['infra_context.json, risk_evaluation_result.json, operational_impact_payloads.json을 받아 보안 위험과 운영 리스크를 함께 검토했습니다.'],
      reasoning: [
        patchRecords.length
          ? `${patchRecords.length}개 자산/CVE 조합에 대해 권장 조치를 산정했습니다.`
          : '패치 전략 결과가 아직 생성되지 않았습니다.',
        firstText(patchRecords, 'reason_summary', '패치 가능성, 서비스 재시작 필요 여부, 남은 불확실성을 함께 검토했습니다.'),
        '자산 상태나 설정 확인이 부족한 경우에는 자동 실행보다 human_review를 우선하도록 판단했습니다.',
      ],
      result: [
        summarizeActions(patchRecords),
        firstText(patchRecords, 'decision', '패치 전략 에이전트가 실행 전 확인해야 할 판단 내용을 정리했습니다.'),
        firstValidation(patchRecords),
        firstUnknowns(patchRecords),
      ],
      handoff: patchExecutionRan
        ? 'patch_strategy_result.json을 패치 실행 에이전트에 전달했습니다.'
        : 'patch_strategy_result.json은 생성되었지만, 이번 실행에서는 패치 실행 에이전트까지 호출하지 않았습니다.',
      highlights: [
        { label: '전략 결과', value: patchRecords.length ? `${patchRecords.length}건` : '-' },
        { label: '대표 조치', value: dominantAction(patchRecords) },
      ],
    },
    {
      key: 'patch_execution',
      title: '패치 실행 에이전트',
      agent: 'patch_exec_agent',
      status: statusFromFiles(latestBundle, 'patch_execution_agent', patchExecutionRan),
      received: ['패치 전략 에이전트가 만든 patch_strategy_result.json이 실행 단계의 입력이 됩니다.'],
      reasoning: patchExecutionRan
        ? ['패치 실행 에이전트가 전략 결과를 바탕으로 실행 또는 실행 계획을 정리했습니다.']
        : ['이번 최신 실행 summary에서는 patch_execution_agent가 포함되지 않았습니다.'],
      result: patchExecutionRan
        ? ['패치 실행 결과는 patch_execution_agent/latest 파일에서 확인할 수 있습니다.', '실행 성공 여부와 상세 로그는 /dev 화면에서 원본 JSON으로 검증할 수 있습니다.']
        : ['따라서 실제 서버 변경이나 패치 적용은 아직 수행되지 않았습니다.', '현재 결과는 패치 전략 단계까지의 권고안이며, 실행 전 사람이 한 번 더 확인할 수 있는 상태입니다.'],
      handoff: '실제 패치 적용이 필요하면 patch_exec_only 실행이 별도로 필요합니다.',
      highlights: [
        { label: '실행 여부', value: patchExecutionRan ? '실행됨' : '미실행' },
      ],
    },
  ];
}

function buildResponseTimeline(root: Record<string, unknown>): TimelineStep[] {
  const flows = buildAgentDataFlows(root);
  return flows.map((flow) => ({
    key: flow.key,
    title: flow.title,
    agent: flow.agent,
    status: flow.status,
    received: flow.received.map((file) => `${file.label}을 입력으로 사용했습니다.`),
    reasoning: ['response.json 기반 결과를 사용자용 설명으로 재구성했습니다.'],
    result: flow.produced.length
      ? flow.produced.map((file) => `${file.label} 결과가 생성되었습니다.`).slice(0, 5)
      : ['아직 생성된 결과가 없습니다.'],
    handoff: '상세 원본은 /dev 화면에서 확인할 수 있습니다.',
    highlights: [
      { label: '출력 파일', value: `${flow.produced.length}개` },
    ],
  }));
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

function arrayOfRecords(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value.filter((item): item is Record<string, unknown> => Boolean(asRecord(item)))
    : [];
}

function collectImpactedAssets(riskResults: Record<string, unknown>[]): string[] {
  const assets = new Set<string>();

  for (const record of riskResults) {
    for (const asset of arrayOfRecords(record.impacted_assets)) {
      const assetId = String(asset.instance_id || asset.asset_id || '').trim();
      if (assetId) assets.add(assetId);
    }
  }

  return [...assets];
}

function publicAssetCount(assets: Record<string, unknown>[]): number {
  return assets.filter((asset) => {
    const metadata = asRecord(asset.metadata);
    const networkContext = asRecord(asset.network_context);
    return Boolean(asset.public_ip)
      || metadata?.network_exposure === 'public'
      || networkContext?.is_internet_facing === true;
  }).length;
}

function componentSummary(assets: Record<string, unknown>[]): string {
  const components = new Map<string, number>();

  for (const asset of assets) {
    for (const software of arrayOfRecords(asset.installed_software)) {
      const product = String(software.product || software.vendor || '').trim();
      if (product) components.set(product, (components.get(product) || 0) + 1);
    }
  }

  const summary = [...components.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 3)
    .map(([product, count]) => `${product} ${count}개`)
    .join(', ');

  return summary
    ? `설치 소프트웨어 중 ${summary}가 주요 분석 대상으로 확인되었습니다.`
    : '설치 소프트웨어 정보가 제한적이어서 추가 확인이 필요합니다.';
}

function firstText(records: Record<string, unknown>[], key: string, fallback: string): string {
  const value = records
    .map((record) => record[key])
    .find((entry) => typeof entry === 'string' && entry.trim());

  return typeof value === 'string' ? value : fallback;
}

function firstImpactedReason(riskResults: Record<string, unknown>[]): string {
  for (const record of riskResults) {
    for (const asset of arrayOfRecords(record.impacted_assets)) {
      const reason = asset.risk_adjustment_reason;
      if (typeof reason === 'string' && reason.trim()) return reason;
    }
  }

  return '자산별 위험도 조정 근거가 아직 충분히 생성되지 않았습니다.';
}

function riskLevelSummary(riskResults: Record<string, unknown>[]): string {
  const counts = new Map<string, number>();

  for (const record of riskResults) {
    for (const asset of arrayOfRecords(record.impacted_assets)) {
      const level = String(asset.calculated_risk || 'UNKNOWN').toUpperCase();
      counts.set(level, (counts.get(level) || 0) + 1);
    }
  }

  const summary = [...counts.entries()]
    .map(([level, count]) => `${level} ${count}개`)
    .join(', ');

  return summary ? `위험도 분포는 ${summary}입니다.` : '위험도 분포를 계산할 수 없습니다.';
}

function dominantRiskLevel(riskResults: Record<string, unknown>[]): string {
  const counts = new Map<string, number>();

  for (const record of riskResults) {
    for (const asset of arrayOfRecords(record.impacted_assets)) {
      const level = String(asset.calculated_risk || '').toUpperCase();
      if (level) counts.set(level, (counts.get(level) || 0) + 1);
    }
  }

  return [...counts.entries()].sort((left, right) => right[1] - left[1])[0]?.[0] || '-';
}

function firstRemediation(riskResults: Record<string, unknown>[]): string {
  for (const record of riskResults) {
    for (const asset of arrayOfRecords(record.impacted_assets)) {
      const remediation = asset.remediation;
      if (typeof remediation === 'string' && remediation.trim()) return `권장 보완 방향은 ${remediation}입니다.`;
    }
  }

  return '권장 보완 방향은 아직 구체화되지 않았습니다.';
}

function summarizeActions(records: Record<string, unknown>[]): string {
  if (records.length === 0) return '아직 권장 조치가 없습니다.';

  const counts = new Map<string, number>();
  for (const record of records) {
    const action = String(record.selected_action || record.decision_type || 'review_required').trim();
    counts.set(action, (counts.get(action) || 0) + 1);
  }

  return [...counts.entries()]
    .map(([action, count]) => `${action} ${count}건`)
    .join(', ');
}

function dominantAction(records: Record<string, unknown>[]): string {
  if (records.length === 0) return '-';

  const counts = new Map<string, number>();
  for (const record of records) {
    const action = String(record.selected_action || record.decision_type || 'review_required').trim();
    counts.set(action, (counts.get(action) || 0) + 1);
  }

  return [...counts.entries()].sort((left, right) => right[1] - left[1])[0]?.[0] || '-';
}

function firstValidation(records: Record<string, unknown>[]): string {
  for (const record of records) {
    const checks = Array.isArray(record.validation_checks) ? record.validation_checks : [];
    const preview = checks
      .filter((item) => typeof item === 'string' && item.trim())
      .slice(0, 2)
      .join(' / ');
    if (preview) return `검증 항목으로는 ${preview} 등이 제시되었습니다.`;
  }

  return '검증 항목은 아직 충분히 정리되지 않았습니다.';
}

function firstUnknowns(records: Record<string, unknown>[]): string {
  for (const record of records) {
    const unknowns = Array.isArray(record.remaining_unknowns) ? record.remaining_unknowns : [];
    const preview = unknowns
      .filter((item) => typeof item === 'string' && item.trim())
      .slice(0, 2)
      .join(' / ');
    if (preview) return `남은 확인 사항은 ${preview} 등입니다.`;
  }

  return '남은 확인 사항은 별도로 기록되지 않았습니다.';
}

function hasValue(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string') return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'object') return Object.keys(value).length > 0;
  return true;
}
