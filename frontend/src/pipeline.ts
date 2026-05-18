import type { AgentDataFlow, DataFile, PipelineForm, Stage, StageState, StopStage, TimelineStep } from './types';

export const stages: Stage[] = [
  {
    key: 'vuln',
    title: 'Vulnerability Collect',
    agent: 'vuln_collector_agent',
    description: 'CVE 데이터를 수집하고 후속 단계 payload를 생성합니다.',
    outputs: [
      'focused_selected_raw_cves.json',
      'risk_assessment_payloads.json',
      'operational_impact_payloads.json',
      'asset_matching_payload.json',
    ],
  },
  {
    key: 'asset',
    title: 'Asset Matching',
    agent: 'infra_matching_agent',
    description: '스택과 자산 정보를 조회해 취약점 영향 대상을 찾습니다.',
    outputs: ['infra_context.json'],
  },
  {
    key: 'risk',
    title: 'Risk Evaluation',
    agent: 'risk_evaluation_agent',
    description: '취약점과 자산 맥락을 결합해 위험도를 산정합니다.',
    outputs: ['risk_evaluation_result.json'],
  },
  {
    key: 'patch',
    title: 'Patch Strategy',
    agent: 'patch_impact_agent',
    description: '위험도와 운영 영향을 기준으로 패치 전략을 판단합니다.',
    outputs: ['patch_strategy_result.json'],
  },
  {
    key: 'patch_execution',
    title: 'Patch Execution',
    agent: 'patch_exec_agent',
    description: '선택된 조치를 실행하거나 실행 계획을 정리합니다.',
    outputs: ['patch_execution_result.json'],
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
  if (form.mode === 'before_exec') return key === 'patch_execution' ? 'blocked' : 'pending';
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
      received: recordAsDataFiles('request_payload.json', 'MultiAIagent/OchestraResult/orchestrator_agent/latest/request_payload.json', compactRecord({
        mode: root.mode,
        stack_name: root.stack_name,
        region: root.region,
        cve_ids: pickFirst(vulnStage?.cve_ids, root.cve_ids),
      })),
      produced: [
        ...recordAsDataFiles(
          'focused_selected_raw_cves.json',
          'MultiAIagent/OchestraResult/vuln_collector_agent/latest/focused_selected_raw_cves.json',
          asRecord(vulnStage?.raw_result),
        ),
        ...recordAsDataFiles(
          'risk_assessment_payloads.json',
          'MultiAIagent/OchestraResult/vuln_collector_agent/latest/risk_assessment_payloads.json',
          asRecord(vulnStage?.risk_assessment_payload),
        ),
        ...recordAsDataFiles(
          'operational_impact_payloads.json',
          'MultiAIagent/OchestraResult/vuln_collector_agent/latest/operational_impact_payloads.json',
          asRecord(vulnStage?.operational_impact_payload),
        ),
        ...recordAsDataFiles(
          'asset_matching_payload.json',
          'MultiAIagent/OchestraResult/vuln_collector_agent/latest/asset_matching_payload.json',
          asRecord(vulnStage?.asset_matching_payload),
        ),
      ],
    },
    {
      key: 'asset',
      title: 'Asset Matching',
      agent: 'infra_matching_agent',
      status: readText(assetStage, 'status'),
      received: recordAsDataFiles(
        'asset_matching_payload.json',
        'MultiAIagent/OchestraResult/vuln_collector_agent/latest/asset_matching_payload.json',
        asRecord(vulnStage?.asset_matching_payload),
      ),
      produced: recordAsDataFiles(
        'infra_context.json',
        'MultiAIagent/OchestraResult/asset_matching_agent/latest/infra_context.json',
        asRecord(infraContext),
      ),
    },
    {
      key: 'risk',
      title: 'Risk Evaluation',
      agent: 'risk_evaluation_agent',
      status: readText(riskStage, 'status'),
      received: [
        ...recordAsDataFiles(
          'infra_context.json',
          'MultiAIagent/OchestraResult/asset_matching_agent/latest/infra_context.json',
          asRecord(infraContext),
        ),
        ...recordAsDataFiles(
          'risk_assessment_payloads.json',
          'MultiAIagent/OchestraResult/vuln_collector_agent/latest/risk_assessment_payloads.json',
          asRecord(vulnStage?.risk_assessment_payload),
        ),
      ],
      produced: recordAsDataFiles(
        'risk_evaluation_result.json',
        'MultiAIagent/OchestraResult/risk_evaluation_agent/latest/risk_evaluation_result.json',
        asRecord(riskResult),
      ),
    },
    {
      key: 'patch',
      title: 'Patch Strategy',
      agent: 'patch_impact_agent',
      status: readText(patchStage, 'status'),
      received: [
        ...recordAsDataFiles(
          'infra_context.json',
          'MultiAIagent/OchestraResult/asset_matching_agent/latest/infra_context.json',
          asRecord(infraContext),
        ),
        ...recordAsDataFiles(
          'risk_evaluation_result.json',
          'MultiAIagent/OchestraResult/risk_evaluation_agent/latest/risk_evaluation_result.json',
          asRecord(riskResult),
        ),
        ...recordAsDataFiles(
          'operational_impact_payloads.json',
          'MultiAIagent/OchestraResult/vuln_collector_agent/latest/operational_impact_payloads.json',
          asRecord(vulnStage?.operational_impact_payload),
        ),
      ],
      produced: recordAsDataFiles(
        'patch_strategy_result.json',
        'MultiAIagent/OchestraResult/patch_impact_agent/latest/patch_strategy_result.json',
        asRecord(patchStrategyResult),
      ),
    },
    {
      key: 'patch_execution',
      title: 'Patch Execution',
      agent: 'patch_exec_agent',
      status: readText(patchExecutionStage, 'status'),
      received: recordAsDataFiles(
        'patch_strategy_result.json',
        'MultiAIagent/OchestraResult/patch_impact_agent/latest/patch_strategy_result.json',
        asRecord(patchStrategyResult),
      ),
      produced: recordAsDataFiles(
        'patch_execution_result.json',
        'MultiAIagent/OchestraResult/patch_execution_agent/latest/patch_execution_result.json',
        asRecord(patchExecutionStage?.result),
      ),
    },
  ];
}

type LatestBundle = {
  agents: Record<string, LatestAgent>;
  conversations: Record<string, DataFile>;
};

type LatestAgent = {
  latestPath: string;
  files: Record<string, DataFile>;
};

function parseLatestBundle(root: Record<string, unknown>): LatestBundle | null {
  const agents = asRecord(root.agents);
  if (!agents) return null;
  const rawConversations = asRecord(root.conversations);

  const parsedAgents: Record<string, LatestAgent> = {};
  const conversations: Record<string, DataFile> = {};

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

  if (rawConversations) {
    for (const [name, rawConversation] of Object.entries(rawConversations)) {
      const conversation = asRecord(rawConversation);
      const path = typeof conversation?.path === 'string'
        ? conversation.path
        : `MultiAIagent/Conversationlog/${name}/latest.json`;

      conversations[name] = {
        label: `${name}/latest.json`,
        path,
        value: conversation && 'value' in conversation ? conversation.value : rawConversation,
      };
    }
  }

  return { agents: parsedAgents, conversations };
}

export function buildConversationFiles(result: unknown): DataFile[] {
  const root = asRecord(result);
  if (!root) return [];

  const latestBundle = parseLatestBundle(root);
  if (!latestBundle) return [];

  return Object.entries(latestBundle.conversations)
    .map(([name, file]) => ({
      ...file,
      label: `${name}/latest.json`,
    }))
    .sort((left, right) => left.label.localeCompare(right.label));
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
      { label: 'Mode', value: '기본 상태' },
      { label: 'Pipeline', value: '5 stages' },
      { label: 'Status', value: '실행 전' },
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
  if (!root) {
    return [
      { label: '실행 상태', value: '기본 상태' },
      { label: '결과 출처', value: '없음' },
      { label: '취약점', value: '입력 대기' },
      { label: '영향 자산', value: '미분석' },
      { label: '권장 조치', value: '실행 후 생성' },
    ];
  }

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

export function buildDefaultResultTimeline(): TimelineStep[] {
  return [
    {
      key: 'vuln',
      title: '취약점 수집 에이전트',
      agent: 'vuln_collector_agent',
      status: 'ready',
      received: ['아직 실행 전 상태입니다.'],
      reasoning: [
        '이 단계는 입력된 CVE를 기준으로 취약점 기본 정보와 약점 의미를 수집합니다.',
        '취약점 2건을 주면 영향 범위, 악용 조건, 자산 확인 포인트를 구조화합니다.',
      ],
      result: [
        '실행 후에는 위험도 평가용 정보와 운영 영향 정보를 정리한 결과가 생성됩니다.',
      ],
      handoff: '생성된 취약점 기준 정보는 자산 매칭, 위험 평가, 패치 전략 단계로 전달됩니다.',
      highlights: [
        { label: '입력', value: 'CVE 목록' },
        { label: '역할', value: '취약점 기준 정보 구조화' },
      ],
    },
    {
      key: 'asset',
      title: '자산 매칭 에이전트',
      agent: 'infra_matching_agent',
      status: 'ready',
      received: ['아직 실행 전 상태입니다.'],
      reasoning: [
        '이 단계는 취약점 기준 정보와 AWS 인프라 자산 정보를 대조합니다.',
        '실제 자산에 nginx, log4j 같은 취약 컴포넌트가 있는지 확인합니다.',
      ],
      result: [
        '실행 후에는 자산별 OS, 설치 소프트웨어, 네트워크 노출, reachability 정보가 정리됩니다.',
      ],
      handoff: '정리된 자산 맥락은 위험 평가와 패치 전략 단계로 전달됩니다.',
      highlights: [
        { label: '입력', value: '취약점 기준 정보 + 인프라 자산' },
        { label: '역할', value: '영향 자산 식별' },
      ],
    },
    {
      key: 'risk',
      title: '위험 평가 에이전트',
      agent: 'risk_evaluation_agent',
      status: 'ready',
      received: ['아직 실행 전 상태입니다.'],
      reasoning: [
        '이 단계는 취약점 기준 정보와 실제 자산 상태를 결합해 위험도를 계산합니다.',
        '취약 버전 존재 여부, 노출 경로, 런타임 조건을 기준으로 자산별 위험도를 조정합니다.',
      ],
      result: [
        '실행 후에는 자산별 위험 수준과 조치 우선순위가 생성됩니다.',
      ],
      handoff: '위험 평가 결과는 패치 전략 단계의 입력으로 전달됩니다.',
      highlights: [
        { label: '입력', value: '취약점 기준 정보 + 자산 맥락' },
        { label: '역할', value: '자산별 위험도 계산' },
      ],
    },
    {
      key: 'patch',
      title: '패치 영향도 에이전트',
      agent: 'patch_impact_agent',
      status: 'ready',
      received: ['아직 실행 전 상태입니다.'],
      reasoning: [
        '이 단계는 위험도와 운영 영향을 함께 보고 패치 전략을 결정합니다.',
        '업그레이드, 수동 검토, 임시 완화 중 어떤 조치가 적절한지 판단합니다.',
      ],
      result: [
        '실행 후에는 patch_strategy_result.json 기준의 전략 결과가 생성됩니다.',
      ],
      handoff: '생성된 전략 결과는 필요 시 패치 실행 단계로 이어집니다.',
      highlights: [
        { label: '입력', value: '위험 평가 + 운영 영향' },
        { label: '역할', value: '패치 전략 판단' },
      ],
    },
    {
      key: 'patch_execution',
      title: '패치 실행 에이전트',
      agent: 'patch_exec_agent',
      status: 'ready',
      received: ['아직 실행 전 상태입니다.'],
      reasoning: [
        '이 단계는 패치 전략 결과를 바탕으로 실제 실행 계획 또는 실행 결과를 정리합니다.',
        '현재 콘솔에서는 안전상 자동 실행보다 실행 계획 정리에 더 가깝게 사용합니다.',
      ],
      result: [
        '실행 후에는 patch_execution_result.json 기준의 결과를 확인할 수 있습니다.',
      ],
      handoff: '최종 실행 결과는 Result와 Dev 화면에서 함께 확인할 수 있습니다.',
      highlights: [
        { label: '입력', value: '패치 전략 결과' },
        { label: '역할', value: '실행 계획/결과 정리' },
      ],
    },
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

  const focusedRaw = asRecord(readFileValue(latestBundle, 'vuln_collector_agent', 'focused_selected_raw_cves.json'));
  const rawRecords = arrayOfRecords(focusedRaw?.records);
  const vulnRecords = arrayOfRecords(asRecord(readFileValue(latestBundle, 'vuln_collector_agent', 'risk_assessment_payloads.json'))?.records);
  const operationalRecords = arrayOfRecords(asRecord(readFileValue(latestBundle, 'vuln_collector_agent', 'operational_impact_payloads.json'))?.records);
  const assetMatchingPayload = asRecord(readFileValue(latestBundle, 'vuln_collector_agent', 'asset_matching_payload.json'));
  const assetMatchingRecords = arrayOfRecords(assetMatchingPayload?.records);
  const infraContext = asRecord(readFileValue(latestBundle, 'asset_matching_agent', 'infra_context.json'));
  const assets = arrayOfRecords(infraContext?.assets);
  const reachability = arrayOfRecords(infraContext?.reachability);
  const riskResults = arrayOfRecords(readFileValue(latestBundle, 'risk_evaluation_agent', 'risk_evaluation_result.json'));
  const patchResult = asRecord(readFileValue(latestBundle, 'patch_impact_agent', 'patch_strategy_result.json'));
  const patchRecords = arrayOfRecords(patchResult?.records);
  const impactedAssets = collectImpactedAssets(riskResults);
  const patchExecutionRan = hasRun('patch_execution_agent', 'patch_execution_agent');
  const vulnSections = buildVulnDetailSections(vulnRecords, operationalRecords, rawRecords, assetMatchingRecords);
  const assetSections = buildAssetDetailSections(assets, reachability);
  const riskSections = buildRiskDetailSections(riskResults, assets, rawRecords);
  const patchSections = buildPatchDetailSections(patchRecords, assets);

  return [
    {
      key: 'vuln',
      title: '취약점 수집 에이전트',
      agent: 'vuln_collector_agent',
      status: statusFromFiles(latestBundle, 'vuln_collector_agent', hasRun('vuln_collector_agent', 'vuln_collector_agent')),
      received: [
        vulnRecords.length
          ? `요청된 CVE ${vulnRecords.length}건을 기준으로 기본 취약점 데이터를 수집했습니다.`
          : '요청된 CVE를 기준으로 기본 취약점 데이터를 수집했습니다.',
      ],
      reasoning: [
        vulnRecords.length
          ? `${vulnRecords.map((record) => record.cve_id).filter(Boolean).join(', ')}에 대해 영향 범위와 약점 의미를 구조화했습니다.`
          : '취약점 기준 정보가 아직 충분히 생성되지 않았습니다.',
        '후속 단계가 바로 사용할 수 있도록 악용 조건, 자산 확인 포인트, 운영 조치 기준까지 함께 정리했습니다.',
      ],
      result: [
        vulnRecords.length
          ? `${vulnRecords.length}건의 취약점 기준 정보와 운영 영향 정보가 생성되었습니다.`
          : '취약점 분석 결과가 비어 있어 다음 단계에서 사용할 근거가 제한됩니다.',
        vulnSections.length
          ? '아래 취약점별 카드에서 실제 결과 JSON 기반 상세 내용을 바로 확인할 수 있습니다.'
          : firstText(vulnRecords, 'affected', '영향받는 제품과 버전 범위를 정리했습니다.'),
        '이 결과는 자산 매칭, 위험 평가, 패치 전략 단계의 입력 데이터로 이어집니다.',
      ],
      handoff: '생성된 취약점 기준 정보는 다음 단계 에이전트들에 전달됩니다.',
      highlights: [
        { label: 'CVE', value: vulnRecords.length ? `${vulnRecords.length}건` : '-' },
        { label: '운영 영향', value: operationalRecords.length ? `${operationalRecords.length}건` : '-' },
      ],
      detailSections: vulnSections,
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
        'private 자산은 NAT outbound 여부와 서브넷 라우트 타입도 함께 정리했습니다.',
      ],
      result: [
        `${publicAssetCount(assets)}개 자산은 public IP 또는 인터넷 노출 신호가 있어 우선 검토 대상으로 볼 수 있습니다.`,
        'nginx와 log4j처럼 CVE와 직접 연결될 수 있는 컴포넌트를 자산별로 식별했습니다.',
        assetSections.length
          ? '아래 자산 구조 카드에서 계층별 자산과 연결 흐름을 실제 infra_context 기준으로 확인할 수 있습니다.'
          : '자산 간 reachability 정보도 함께 정리해 web, app, db 계층의 연결 흐름을 확인할 수 있게 했습니다.',
        '이 자산 맥락은 위험 평가 에이전트가 CVE별 실제 영향도를 계산하는 근거가 됩니다.',
      ],
      handoff: 'infra_context.json을 위험 평가와 패치 전략 에이전트에 전달합니다.',
      highlights: [
        { label: '자산', value: `${assets.length}개` },
        { label: '인터넷 노출', value: `${publicAssetCount(assets)}개` },
        { label: 'NAT outbound', value: `${assets.filter((asset) => assetHasNatEgress(asset)).length}개` },
        { label: '서브넷 유형', value: summarizeAssetRouteTypes(assets) },
      ],
      detailSections: assetSections,
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
        riskSections.length
          ? '아래 자산별 위험 카드에서 실제 영향 대상과 위험도 조정 이유를 바로 확인할 수 있습니다.'
          : firstImpactedReason(riskResults),
        '확인되지 않은 런타임 상태는 안전하다고 가정하지 않고, 필요한 경우 위험도를 보수적으로 유지했습니다.',
      ],
      result: [
        impactedAssets.length
          ? `${impactedAssets.length}개 자산이 실제 영향 가능 대상으로 분류되었습니다.`
          : '현재 결과에서 영향 자산은 확인되지 않았습니다.',
        riskLevelSummary(riskResults),
        '위험도는 설치 버전, 노출 수준, 실행 권한, 취약점 성립 조건 근거를 기준으로 계산했습니다.',
        '이 위험 평가 결과는 패치 전략 에이전트가 자동 조치, 수동 검토, 임시 완화 중 무엇이 적절한지 판단하는 기준이 됩니다.',
      ],
      handoff: 'risk_evaluation_result.json을 패치 전략 에이전트에 전달합니다.',
      highlights: [
        { label: '영향 자산', value: `${impactedAssets.length}개` },
        { label: '위험도', value: dominantRiskLevel(riskResults) },
      ],
      detailSections: riskSections,
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
        patchActionSummary(patchRecords),
      ],
      result: [
        summarizeActions(patchRecords),
        firstText(patchRecords, 'decision', '패치 전략 에이전트가 실행 전 확인해야 할 판단 내용을 정리했습니다.'),
        firstValidation(patchRecords),
        firstUnknowns(patchRecords),
        'asset follow-up 질의가 발생한 경우에는 OchestraResult가 아니라 Conversationlog/PatchToAsset/latest.json에 별도로 정리됩니다.',
      ],
      handoff: patchExecutionRan
        ? 'patch_strategy_result.json을 패치 실행 에이전트에 전달했습니다.'
        : 'patch_strategy_result.json은 생성되었지만, 이번 실행에서는 패치 실행 에이전트까지 호출하지 않았습니다.',
      highlights: [
        { label: '전략 결과', value: patchRecords.length ? `${patchRecords.length}건` : '-' },
        { label: '대표 조치', value: dominantAction(patchRecords) },
        { label: '즉시 패치', value: `${countPatchAction(patchRecords, 'apply_patch_now')}건` },
        { label: '계획 패치', value: `${countPatchAction(patchRecords, 'apply_patch_planned')}건` },
      ],
      detailSections: patchSections,
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

function recordAsDataFiles(label: string, path: string, value: Record<string, unknown> | null): DataFile[] {
  return value && Object.keys(value).length > 0
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
    return Boolean(asset.public_ip)
      || metadata?.network_exposure === 'public'
      || metadata?.internet_route_via_igw === true;
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

function countPatchAction(records: Record<string, unknown>[], actionName: string): number {
  return records.filter((record) => String(record.selected_action || record.decision_type || '').trim() === actionName).length;
}

function patchActionSummary(records: Record<string, unknown>[]): string {
  if (records.length === 0) return '패치 전략 결과가 아직 생성되지 않았습니다.';

  const applyNow = countPatchAction(records, 'apply_patch_now');
  const applyPlanned = countPatchAction(records, 'apply_patch_planned');
  const humanReview = countPatchAction(records, 'human_review');
  const manualMitigation = countPatchAction(records, 'apply_mitigation');

  const parts = [
    applyNow > 0 ? `즉시 패치 ${applyNow}건` : '',
    applyPlanned > 0 ? `계획 패치 ${applyPlanned}건` : '',
    manualMitigation > 0 ? `임시 완화 ${manualMitigation}건` : '',
    humanReview > 0 ? `수동 검토 ${humanReview}건` : '',
  ].filter(Boolean);

  return parts.length > 0
    ? `전략 분포는 ${parts.join(', ')}입니다.`
    : '자산 상태나 설정 확인이 부족한 경우에는 자동 실행보다 human_review를 우선하도록 판단했습니다.';
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

function buildVulnDetailSections(
  vulnRecords: Record<string, unknown>[],
  operationalRecords: Record<string, unknown>[],
  rawRecords: Record<string, unknown>[],
  assetMatchingRecords: Record<string, unknown>[],
): NonNullable<TimelineStep['detailSections']> {
  const operationalByCve = new Map(operationalRecords.map((record) => [String(record.cve_id || ''), record]));
  const rawByCve = new Map(rawRecords.map((record) => [String(record.cve_id || ''), record]));
  const assetByCve = new Map(assetMatchingRecords.map((record) => [String(record.cve_id || ''), record]));

  return vulnRecords.map((record, index) => {
    const cveId = String(record.cve_id || '').trim() || `unknown-${index}`;
    const operational = operationalByCve.get(cveId) || null;
    const raw = rawByCve.get(cveId) || null;
    const asset = assetByCve.get(cveId) || null;

    const title = readString(record, 'title') || readString(raw, 'title') || '제목 정보 없음';
    const cvss = summarizeCvss(readRecord(raw, 'cvss'));
    const weakness = summarizeWeakness(raw);
    const versionRange = summarizeVersionRange(asset, record);
    const remediation = readString(operational, 'primary_remediation') || '주요 조치 정보 없음';
    const exploit = readString(record, 'exploit_conditions') || '악용 조건 정보 없음';
    const operationalRisk = readString(operational, 'operational_risk') || '운영 영향 정보 없음';
    const assetChecks = summarizeChecklistQuestions(arrayOfRecords(record.asset_checks), 2, '자산 확인 포인트 정보 없음');
    const fallbackMitigations = summarizeFallbackMitigations(arrayOfRecords(operational?.fallback_mitigations), 2, '임시 완화 조치 정보 없음');

    return {
      title: `취약점 ${index + 1}. ${cveId}`,
      summary: title,
      fields: [
        { label: 'CVSS', value: cvss },
        { label: '약점 유형', value: weakness },
        { label: '영향 버전', value: versionRange },
        { label: '주요 조치', value: remediation },
      ],
      bullets: [
        `악용 조건: ${exploit}`,
        `자산 확인 포인트: ${assetChecks}`,
        `운영 영향: ${operationalRisk}`,
        `임시 완화 조치: ${fallbackMitigations}`,
      ],
    };
  });
}

function readString(value: Record<string, unknown> | null | undefined, key: string): string {
  const raw = value?.[key];
  return typeof raw === 'string' && raw.trim() ? raw.trim() : '';
}

function summarizeCvss(cvss: Record<string, unknown> | null): string {
  if (!cvss) return '정보 없음';

  const score = cvss.score;
  const details = readRecord(cvss, 'vector_details');
  const attackVector = readString(details, 'attack_vector');
  const attackComplexity = readString(details, 'attack_complexity');
  const severity = [attackVector, attackComplexity].filter(Boolean).join(' / ');

  if (typeof score === 'number') {
    return severity ? `${score.toFixed(1)} (${severity})` : score.toFixed(1);
  }

  return severity || '정보 없음';
}

function summarizeWeakness(raw: Record<string, unknown> | null): string {
  if (!raw) return '정보 없음';

  const weaknessIds = Array.isArray(raw.weaknesses)
    ? raw.weaknesses.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
    : [];
  const cweDetails = arrayOfRecords(raw.cwe_details);
  const cweName = readString(cweDetails[0], 'name');

  if (weaknessIds.length && cweName) return `${weaknessIds[0]} · ${cweName}`;
  if (weaknessIds.length) return weaknessIds.join(', ');
  if (cweName) return cweName;
  return '정보 없음';
}

function summarizeVersionRange(asset: Record<string, unknown> | null, riskRecord: Record<string, unknown>): string {
  const ranges = Array.isArray(asset?.affected_version_range)
    ? asset?.affected_version_range.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
    : [];

  if (ranges.length > 0) return ranges.join(', ');

  const affected = readString(riskRecord, 'affected');
  return affected || '정보 없음';
}

function summarizeChecklistQuestions(checks: Record<string, unknown>[], max: number, fallback: string): string {
  const questions = checks
    .map((check) => readString(check, 'question'))
    .filter(Boolean)
    .slice(0, max);

  return questions.length > 0 ? questions.join(' / ') : fallback;
}

function summarizeFallbackMitigations(
  mitigations: Record<string, unknown>[],
  max: number,
  fallback: string,
): string {
  const items = mitigations
    .map((item) => readString(item, 'mitigation'))
    .filter(Boolean)
    .slice(0, max);

  return items.length > 0 ? items.join(' / ') : fallback;
}

function buildAssetDetailSections(
  assets: Record<string, unknown>[],
  reachability: Record<string, unknown>[],
): NonNullable<TimelineStep['detailSections']> {
  const tierOrder = ['web', 'app', 'db'];
  const tierLabels: Record<string, string> = {
    web: 'WEB 계층',
    app: 'APP 계층',
    db: 'DB 계층',
  };

  const sections: NonNullable<TimelineStep['detailSections']> = [];

  for (const tier of tierOrder) {
    const tierAssets = assets.filter((asset) => String(asset.tier || '').toLowerCase() === tier);
    if (tierAssets.length === 0) continue;

    const publicCount = tierAssets.filter((asset) => Boolean(readString(asset, 'public_ip')) || readString(asRecord(asset.metadata), 'network_exposure') === 'public').length;
    const natEgressCount = tierAssets.filter((asset) => assetHasNatEgress(asset)).length;
    const softwareSummary = summarizeAssetSoftware(tierAssets);
    const portSummary = summarizeAssetPorts(tierAssets);
    const hostSummary = summarizeAssetHosts(tierAssets, 3);
    const routeSummary = summarizeAssetRouteTypes(tierAssets);

    sections.push({
      title: tierLabels[tier] || `${tier.toUpperCase()} 계층`,
      summary: `${tierAssets.length}개 자산`,
      fields: [
        { label: '자산 수', value: `${tierAssets.length}개` },
        { label: 'Public 노출', value: `${publicCount}개` },
        { label: 'NAT outbound', value: `${natEgressCount}개` },
        { label: '서브넷 유형', value: routeSummary },
        { label: '주요 소프트웨어', value: softwareSummary },
        { label: '주요 포트', value: portSummary },
      ],
      bullets: [
        `대표 자산: ${hostSummary}`,
        natEgressCount > 0
          ? `이 계층의 ${natEgressCount}개 자산은 NAT를 통해 외부 egress가 가능합니다.`
          : '이 계층에서 NAT outbound 신호는 확인되지 않았습니다.',
      ],
    });
  }

  if (reachability.length > 0) {
    sections.push({
      title: '연결 흐름',
      summary: '계층 간 reachability',
      fields: [
        { label: '흐름 수', value: `${reachability.length}개` },
        { label: '대표 구조', value: summarizeReachability(reachability) },
      ],
      bullets: reachability.map((edge) => {
        const from = readString(edge, 'from') || 'unknown';
        const to = readString(edge, 'to') || 'unknown';
        const ports = Array.isArray(edge.ports) ? edge.ports.map(String).join(', ') : '-';
        return `${from.toUpperCase()} -> ${to.toUpperCase()} : ${ports}`;
      }),
    });
  }

  return sections;
}

function buildRiskDetailSections(
  riskResults: Record<string, unknown>[],
  assets: Record<string, unknown>[],
  rawRecords: Record<string, unknown>[],
): NonNullable<TimelineStep['detailSections']> {
  const assetById = new Map<string, Record<string, unknown>>();
  const rawByCve = new Map<string, Record<string, unknown>>();
  for (const asset of assets) {
    const assetId = readString(asset, 'asset_id');
    if (assetId) assetById.set(assetId, asset);
  }
  for (const raw of rawRecords) {
    const cveId = readString(raw, 'cve_id');
    if (cveId) rawByCve.set(cveId, raw);
  }

  const groups = new Map<
    string,
    {
      asset: Record<string, unknown> | null;
      hostname: string;
      tier: string;
      exposure: string;
      entries: Array<{
        cveId: string;
        title: string;
        baseRisk: string;
        adjustedRisk: string;
        reason: string;
      }>;
    }
  >();

  for (const record of riskResults) {
    const cveId = readString(record, 'cve_id') || 'unknown-cve';
    const title = readString(record, 'title');
    for (const impacted of arrayOfRecords(record.impacted_assets)) {
      const instanceId = readString(impacted, 'instance_id');
      if (!instanceId) continue;
      const asset = assetById.get(instanceId) || null;
      const raw = rawByCve.get(cveId) || null;
      const hostname = readString(asset, 'hostname') || instanceId;
      const tier = readString(asset, 'tier').toUpperCase() || 'UNKNOWN';
      const exposure = readString(impacted, 'exposure_level') || '정보 없음';
      const risk = readString(impacted, 'calculated_risk') || 'UNKNOWN';
      const reason = readString(impacted, 'risk_adjustment_reason') || '위험도 조정 근거 정보 없음';

      if (!groups.has(instanceId)) {
        groups.set(instanceId, {
          asset,
          hostname,
          tier,
          exposure,
          entries: [],
        });
      }

      groups.get(instanceId)?.entries.push({
        cveId,
        title: title || '',
        baseRisk: summarizeBaseRisk(raw),
        adjustedRisk: summarizeAdjustedRisk(raw, risk),
        reason,
      });
    }
  }

  const sections: NonNullable<TimelineStep['detailSections']> = [];
  let index = 0;
  for (const [instanceId, group] of groups.entries()) {
    index += 1;
    const asset = group.asset;
    const ip = readString(asset, 'public_ip') || readString(asset, 'private_ip') || '정보 없음';
    const software = summarizeAssetSoftware(asset ? [asset] : []);
    const ports = summarizeAssetPorts(asset ? [asset] : []);

    sections.push({
      title: `자산 ${index}. ${group.tier} / ${group.hostname}`,
      summary: `${group.entries.length}개 CVE 영향 평가`,
      fields: [
        { label: '노출 수준', value: group.exposure },
        { label: '주소', value: ip },
        { label: '탐지 소프트웨어', value: software },
        { label: '주요 포트', value: ports },
        { label: '영향 CVE 수', value: `${group.entries.length}개` },
      ],
      bullets: [
        `인스턴스 ID: ${instanceId}`,
        ...group.entries.map((entry) =>
          `${entry.cveId}${entry.title ? ` · ${entry.title}` : ''} | 기준 위험도 ${entry.baseRisk} | 조정 결과 ${entry.adjustedRisk} | ${entry.reason}`,
        ),
      ],
    });
  }

  return sections;
}

function buildPatchDetailSections(
  patchRecords: Record<string, unknown>[],
  assets: Record<string, unknown>[],
): NonNullable<TimelineStep['detailSections']> {
  const assetById = new Map<string, Record<string, unknown>>();
  for (const asset of assets) {
    const assetId = readString(asset, 'asset_id');
    if (assetId) assetById.set(assetId, asset);
  }

  return patchRecords.map((record, index) => {
    const assetId = readString(record, 'asset_id') || `unknown-asset-${index}`;
    const asset = assetById.get(assetId) || null;
    const hostname = readString(asset, 'hostname') || assetId;
    const tier = readString(asset, 'tier').toUpperCase() || 'UNKNOWN';
    const cveId = readString(record, 'cve_id') || 'unknown-cve';
    const action = readString(record, 'selected_action') || '정보 없음';
    const confidence = readString(record, 'confidence').toUpperCase() || '정보 없음';
    const currentVersion = readString(record, 'current_version') || '정보 없음';
    const targetVersion = readString(record, 'target_version') || '정보 없음';
    const patchFeasible = readString(record, 'patch_feasible') || '정보 없음';
    const mitigationAvailable = readString(record, 'mitigation_available') || '정보 없음';
    const changeSurface = readString(record, 'change_surface') || '정보 없음';
    const deploymentRequirement = readString(record, 'deployment_requirement') || '정보 없음';
    const mitigationSummary = readString(record, 'mitigation_summary') || '없음';
    const reasonSummary = readString(record, 'reason_summary') || '판단 근거 정보 없음';
    const decision = readString(record, 'decision') || '전략 판단 정보 없음';
    const validationChecks = Array.isArray(record.validation_checks)
      ? record.validation_checks.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
      : [];
    const remainingUnknowns = Array.isArray(record.remaining_unknowns)
      ? record.remaining_unknowns.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
      : [];

    return {
      title: `전략 ${index + 1}. ${tier} / ${hostname}`,
      summary: `${cveId} · ${readString(record, 'affected_component') || 'component 정보 없음'}`,
      fields: [
        { label: '권장 조치', value: action },
        { label: '현재 버전', value: currentVersion },
        { label: '목표 버전', value: targetVersion },
        { label: '변경 대상', value: changeSurface },
        { label: '배포 요구', value: deploymentRequirement },
        { label: '패치 가능', value: patchFeasible },
        { label: '완화 가능', value: mitigationAvailable },
        { label: '신뢰도', value: confidence },
      ],
      bullets: [
        `자산 ID: ${assetId}`,
        `판단 근거: ${reasonSummary}`,
        `전략 결정: ${decision}`,
        `임시 완화 조치: ${mitigationSummary}`,
        validationChecks.length > 0
          ? `검증 항목: ${validationChecks.slice(0, 3).join(' / ')}`
          : '검증 항목: 별도 제시 없음',
        remainingUnknowns.length > 0
          ? `남은 확인 사항: ${remainingUnknowns.join(' / ')}`
          : '남은 확인 사항: 없음',
      ],
    };
  });
}

function summarizeAssetSoftware(assets: Record<string, unknown>[]): string {
  const counts = new Map<string, number>();
  for (const asset of assets) {
    for (const software of arrayOfRecords(asset.installed_software)) {
      const product = readString(software, 'product') || readString(software, 'vendor');
      if (!product) continue;
      counts.set(product, (counts.get(product) || 0) + 1);
    }
  }

  const summary = [...counts.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 2)
    .map(([product, count]) => `${product} ${count}개`)
    .join(' / ');

  return summary || '확인된 소프트웨어 없음';
}

function summarizeAssetPorts(assets: Record<string, unknown>[]): string {
  const ports = new Set<string>();
  for (const asset of assets) {
    const networkContext = asRecord(asset.network_context);
    const listeningPorts = Array.isArray(networkContext?.listening_ports) ? networkContext?.listening_ports : [];
    for (const port of listeningPorts) ports.add(String(port));
  }

  const summary = [...ports].sort((left, right) => Number(left) - Number(right)).join(', ');
  return summary || '-';
}

function summarizeAssetHosts(assets: Record<string, unknown>[], max: number): string {
  const labels = assets
    .slice(0, max)
    .map((asset) => {
      const hostname = readString(asset, 'hostname') || readString(asset, 'asset_id');
      const ip = readString(asset, 'public_ip') || readString(asset, 'private_ip');
      return ip ? `${hostname} (${ip})` : hostname;
    })
    .filter(Boolean);

  const suffix = assets.length > max ? ` 외 ${assets.length - max}개` : '';
  return labels.length > 0 ? `${labels.join(' / ')}${suffix}` : '자산 정보 없음';
}

function summarizeAssetRouteTypes(assets: Record<string, unknown>[]): string {
  const counts = new Map<string, number>();

  for (const asset of assets) {
    const metadata = asRecord(asset.metadata);
    const routeType = readString(metadata, 'subnet_route_type') || 'unknown';
    counts.set(routeType, (counts.get(routeType) || 0) + 1);
  }

  const summary = [...counts.entries()]
    .sort((left, right) => right[1] - left[1])
    .map(([routeType, count]) => `${routeType} ${count}개`)
    .join(' / ');

  return summary || 'unknown';
}

function assetHasNatEgress(asset: Record<string, unknown>): boolean {
  const metadata = asRecord(asset.metadata);
  return metadata?.internet_egress_via_nat === true;
}

function summarizeReachability(reachability: Record<string, unknown>[]): string {
  const summary = reachability
    .slice(0, 3)
    .map((edge) => {
      const from = readString(edge, 'from') || 'unknown';
      const to = readString(edge, 'to') || 'unknown';
      const ports = Array.isArray(edge.ports) ? edge.ports.map(String).join(',') : '-';
      return `${from}->${to}:${ports}`;
    })
    .join(' / ');

  return summary || '-';
}

function summarizeBaseRisk(raw: Record<string, unknown> | null): string {
  const cvss = readRecord(raw, 'cvss');
  if (!cvss) return '정보 없음';

  const score = cvss.score;
  if (typeof score !== 'number') return '정보 없음';

  const severity = severityFromCvss(score);
  return `${score.toFixed(1)} · ${severity}`;
}

function summarizeAdjustedRisk(raw: Record<string, unknown> | null, calculatedRisk: string): string {
  const cvss = readRecord(raw, 'cvss');
  const score = cvss?.score;
  if (typeof score === 'number') {
    return `${severityFromCvss(score)} -> ${calculatedRisk || 'UNKNOWN'}`;
  }

  return calculatedRisk || 'UNKNOWN';
}

function severityFromCvss(score: number): string {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'NONE';
}

function hasValue(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string') return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'object') return Object.keys(value).length > 0;
  return true;
}
