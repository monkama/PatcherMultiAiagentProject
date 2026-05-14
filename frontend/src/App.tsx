import { useCallback, useEffect, useMemo, useState } from 'react';
import { Button } from '@wanteddev/wds';
import {
  buildAgentDataFlows,
  buildResultTimeline,
  defaultForm,
  formatUnknownDataBlock,
  getStageState,
  stages,
  summarizePipelineResult,
  summarizeUserResult,
} from './pipeline';
import type { AgentDataFlow, DataFile, PipelineForm, PipelineMode, StageState, StopStage, TimelineStep } from './types';

type View = 'workflow' | 'result' | 'dev';
type StageKey = Exclude<StopStage, ''>;
type RunState = 'idle' | 'running' | 'success' | 'error' | 'blocked';

const modeOptions: Array<{ value: PipelineMode; label: string }> = [
  { value: 'full', label: 'Full' },
  { value: 'vuln_only', label: 'Vuln' },
  { value: 'asset_only', label: 'Asset' },
  { value: 'risk_only', label: 'Risk' },
  { value: 'patch_only', label: 'Patch' },
  { value: 'before_exec', label: 'Exec 전' },
  { value: 'patch_exec_only', label: 'Exec' },
  { value: 'test', label: 'Test' },
];

const stopStageOptions: Array<{ value: StopStage; label: string }> = [
  { value: '', label: '끝까지' },
  { value: 'vuln', label: 'Vuln' },
  { value: 'asset', label: 'Asset' },
  { value: 'risk', label: 'Risk' },
  { value: 'patch', label: 'Patch' },
  { value: 'patch_execution', label: 'Exec' },
];

const stageOrder: StageKey[] = ['vuln', 'asset', 'risk', 'patch', 'patch_execution'];

function App() {
  const [form, setForm] = useState<PipelineForm>(defaultForm);
  const [view, setView] = useState<View>(() => getViewFromPath());
  const [resultJson, setResultJson] = useState(() => localStorage.getItem('pipeline-result-json') || '');
  const [loadStatus, setLoadStatus] = useState('');
  const [isLoadingLocalResult, setIsLoadingLocalResult] = useState(false);
  const [runState, setRunState] = useState<RunState>('idle');
  const [runMessage, setRunMessage] = useState('아직 실행하지 않았습니다.');
  const [runningStageKey, setRunningStageKey] = useState<StageKey | null>(null);
  const [runTargetStages, setRunTargetStages] = useState<StageKey[]>([]);
  const [completedStageKeys, setCompletedStageKeys] = useState<StageKey[]>([]);

  useEffect(() => {
    const handlePopState = () => setView(getViewFromPath());
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  useEffect(() => {
    localStorage.setItem('pipeline-result-json', resultJson);
  }, [resultJson]);

  const parsedResult = useMemo(() => parseResultJson(resultJson), [resultJson]);
  const dataFlows = useMemo(
    () => (parsedResult.value ? buildAgentDataFlows(parsedResult.value) : []),
    [parsedResult.value],
  );
  const timelineSteps = useMemo(
    () => (parsedResult.value ? buildResultTimeline(parsedResult.value) : []),
    [parsedResult.value],
  );
  const userSummary = useMemo(() => summarizeUserResult(parsedResult.value), [parsedResult.value]);
  const devSummary = useMemo(() => summarizePipelineResult(parsedResult.value), [parsedResult.value]);

  const updateForm = <K extends keyof PipelineForm>(key: K, value: PipelineForm[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const navigate = (nextView: View) => {
    const nextPath = nextView === 'result' ? '/result' : nextView === 'dev' ? '/dev' : '/';
    window.history.pushState(null, '', nextPath);
    setView(nextView);
  };

  const loadLatestResult = useCallback(async () => {
    setIsLoadingLocalResult(true);
    setLoadStatus('');

    try {
      const response = await fetch('/api/local-results/latest', { cache: 'no-store' });
      const text = await response.text();

      if (!response.ok) {
        throw new Error('OchestraResult latest 파일을 찾지 못했습니다.');
      }

      const parsed = JSON.parse(text) as unknown;
      setResultJson(JSON.stringify(parsed, null, 2));
      setLoadStatus(`OchestraResult 최신 파일을 불러왔습니다. ${formatLatestCreatedAt(parsed)}`);
    } catch (error) {
      setLoadStatus(error instanceof Error ? error.message : '로컬 결과를 불러오지 못했습니다.');
    } finally {
      setIsLoadingLocalResult(false);
    }
  }, []);

  useEffect(() => {
    if (view !== 'workflow' && !resultJson.trim()) {
      void loadLatestResult();
    }
  }, [view, resultJson, loadLatestResult]);

  const runPipeline = async () => {
    const blockReason = getBlockedRunReason(form);
    if (blockReason) {
      setRunState('blocked');
      setRunMessage(blockReason);
      setRunningStageKey(null);
      setRunTargetStages([]);
      return;
    }

    const targetStages = getRunTargetStages(form);
    const latestBeforeRun = parsedResult.value ?? await fetchLatestBundle();
    const previousRunTag = getSummaryRunTag(extractLatestSummary(latestBeforeRun));
    let progressIndex = 0;
    let progressTimer: number | undefined;
    let completionCheckInFlight = false;
    let settledByLatestResult = false;
    const abortController = new AbortController();

    const completeRun = (bundle: unknown, summary: unknown) => {
      setResultJson(JSON.stringify(bundle, null, 2));
      setCompletedStageKeys(getCompletedStages(summary));
      setRunState('success');
      setRunMessage('실행 완료. Result와 Dev 화면에서 최신 결과를 확인할 수 있습니다.');
      setRunningStageKey(null);
    };

    const completionTimer = window.setInterval(() => {
      if (completionCheckInFlight || settledByLatestResult) return;
      completionCheckInFlight = true;

      void fetchLatestBundle()
        .then((bundle) => {
          if (!bundle || settledByLatestResult) return;

          const summary = extractLatestSummary(bundle);
          const runTag = getSummaryRunTag(summary);
          if (runTag && runTag !== previousRunTag) {
            settledByLatestResult = true;
            abortController.abort();
            completeRun(bundle, summary);
          }
        })
        .catch(() => {
          // The main request still owns the final error state.
        })
        .finally(() => {
          completionCheckInFlight = false;
        });
    }, 5000);

    setRunState('running');
    setRunMessage('오케스트레이터를 실행하는 중입니다.');
    setRunTargetStages(targetStages);
    setCompletedStageKeys([]);
    setRunningStageKey(targetStages[0] ?? null);

    if (targetStages.length > 1) {
      progressTimer = window.setInterval(() => {
        progressIndex = Math.min(progressIndex + 1, targetStages.length - 1);
        setRunningStageKey(targetStages[progressIndex] ?? null);
      }, 5000);
    }

    try {
      const response = await fetch('/api/run-orchestrator', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ form }),
        signal: abortController.signal,
      });
      const payload = await response.json() as { bundle?: unknown; summary?: unknown; message?: string; error?: string };

      if (!response.ok) {
        throw new Error(payload.error || payload.message || '실행에 실패했습니다.');
      }

      if (payload.bundle) {
        completeRun(payload.bundle, payload.summary ?? extractLatestSummary(payload.bundle));
      } else {
        await loadLatestResult();
        setCompletedStageKeys(getCompletedStages(payload.summary));
        setRunState('success');
        setRunMessage('실행 완료. Result와 Dev 화면에서 최신 결과를 확인할 수 있습니다.');
        setRunningStageKey(null);
      }
    } catch (error) {
      if (settledByLatestResult && error instanceof DOMException && error.name === 'AbortError') {
        return;
      }
      setRunState('error');
      setRunMessage(error instanceof Error ? error.message : '실행 중 알 수 없는 오류가 발생했습니다.');
      setRunningStageKey(null);
    } finally {
      if (progressTimer) window.clearInterval(progressTimer);
      window.clearInterval(completionTimer);
    }
  };

  return (
    <main className="app-shell">
      <section className="topbar">
        <div>
          <p className="eyebrow">Patcher Multi AI Agent</p>
          <h1>보안 패치 워크플로우 콘솔</h1>
        </div>
        <div className="topbar-actions">
          <div className="view-tabs" aria-label="화면 전환">
            <button
              type="button"
              className={view === 'workflow' ? 'active' : ''}
              onClick={() => navigate('workflow')}
            >
              Workflow
            </button>
            <button
              type="button"
              className={view === 'result' ? 'active' : ''}
              onClick={() => navigate('result')}
            >
              Result
            </button>
            <button
              type="button"
              className={view === 'dev' ? 'active' : ''}
              onClick={() => navigate('dev')}
            >
              Dev
            </button>
          </div>
        </div>
      </section>

      {view === 'workflow' ? (
        <WorkflowView
          form={form}
          updateForm={updateForm}
          runState={runState}
          runMessage={runMessage}
          runningStageKey={runningStageKey}
          runTargetStages={runTargetStages}
          completedStageKeys={completedStageKeys}
          runPipeline={runPipeline}
        />
      ) : view === 'result' ? (
        <ResultTimelineView
          error={parsedResult.error}
          summary={userSummary}
          timelineSteps={timelineSteps}
          loadStatus={loadStatus}
          isLoadingLocalResult={isLoadingLocalResult}
          loadLatestResult={loadLatestResult}
        />
      ) : (
        <DevView
          summary={devSummary}
          dataFlows={dataFlows}
        />
      )}
    </main>
  );
}

function WorkflowView({
  form,
  updateForm,
  runState,
  runMessage,
  runningStageKey,
  runTargetStages,
  completedStageKeys,
  runPipeline,
}: {
  form: PipelineForm;
  updateForm: <K extends keyof PipelineForm>(key: K, value: PipelineForm[K]) => void;
  runState: RunState;
  runMessage: string;
  runningStageKey: StageKey | null;
  runTargetStages: StageKey[];
  completedStageKeys: StageKey[];
  runPipeline: () => Promise<void>;
}) {
  const blockReason = getBlockedRunReason(form);

  return (
    <section className="workflow-grid">
      <aside className="control-panel" aria-label="파이프라인 입력">
        <div className="panel-header">
          <h2>실행 설정</h2>
          <span className="status-pill">front</span>
        </div>

        <label className="field">
          <span>실행 모드</span>
          <div className="segmented-control">
            {modeOptions.map((option) => (
              <button
                key={option.value}
                type="button"
                className={form.mode === option.value ? 'selected' : ''}
                onClick={() => updateForm('mode', option.value)}
              >
                {option.label}
              </button>
            ))}
          </div>
        </label>

        <div className="field-row">
          <label className="field">
            <span>Stack</span>
            <input
              value={form.stack_name}
              onChange={(event) => updateForm('stack_name', event.target.value)}
            />
          </label>
          <label className="field">
            <span>Region</span>
            <input
              value={form.region}
              onChange={(event) => updateForm('region', event.target.value)}
            />
          </label>
        </div>

        <label className="field">
          <span>CVE IDs</span>
          <input
            value={form.cve_ids}
            onChange={(event) => updateForm('cve_ids', event.target.value)}
            placeholder="CVE-2021-23017, CVE-2021-44228"
          />
        </label>

        {form.mode === 'test' ? (
          <label className="field">
            <span>중단 단계</span>
            <select
              value={form.stop_stage}
              onChange={(event) => updateForm('stop_stage', event.target.value as StopStage)}
            >
              {stopStageOptions.map((option) => (
                <option key={option.value || 'none'} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
        ) : null}

        <label className="toggle-field">
          <input
            type="checkbox"
            checked={form.allow_followup}
            onChange={(event) => updateForm('allow_followup', event.target.checked)}
          />
          <span>Patch 단계에서 asset follow-up 허용</span>
        </label>

        <div className={`run-panel ${runState}`}>
          <Button
            type="button"
            variant="solid"
            color="primary"
            size="medium"
            onClick={runPipeline}
            disabled={runState === 'running'}
          >
            {getRunButtonLabel(runState)}
          </Button>
          <p className={blockReason ? 'error-text' : runState === 'success' ? 'success-text' : 'muted-text'}>
            {blockReason || runMessage}
          </p>
        </div>
      </aside>

      <section className="pipeline-panel" aria-label="파이프라인 단계">
        <div className="panel-header">
          <h2>워크플로우</h2>
          <span className="muted-text">기존 Python 실행 흐름 기준</span>
        </div>
        <div className="stage-list">
          {stages.map((stage, index) => {
            const state = getVisualStageState(
              form,
              stage.key,
              runState,
              runningStageKey,
              runTargetStages,
              completedStageKeys,
            );
            return (
              <article className={`stage-card ${state}`} key={stage.key}>
                <div className="stage-index">{index + 1}</div>
                <div>
                  <div className="stage-heading">
                    <h3>{stage.title}</h3>
                    <span>{stage.agent}</span>
                  </div>
                  <p>{stage.description}</p>
                  <div className="chip-row">
                    {stage.outputs.map((output) => (
                      <span className="chip" key={output}>
                        {output}
                      </span>
                    ))}
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      </section>
    </section>
  );
}

function ResultTimelineView({
  error,
  summary,
  timelineSteps,
  loadStatus,
  isLoadingLocalResult,
  loadLatestResult,
}: {
  error: string;
  summary: Array<{ label: string; value: string }>;
  timelineSteps: TimelineStep[];
  loadStatus: string;
  isLoadingLocalResult: boolean;
  loadLatestResult: () => Promise<void>;
}) {
  return (
    <section className="result-view">
      <section className="result-hero" aria-label="실행 결과 요약">
        <div>
          <p className="eyebrow">Agent Timeline</p>
          <h2>에이전트 실행 흐름</h2>
          <p className="panel-subtitle">
            각 에이전트가 받은 정보, 판단 근거, 만든 결과를 사용자가 읽기 쉬운 순서로 정리했습니다.
          </p>
        </div>
        <div className="result-actions">
          <Button
            type="button"
            variant="solid"
            color="primary"
            size="medium"
            onClick={loadLatestResult}
            disabled={isLoadingLocalResult}
          >
            {isLoadingLocalResult ? '불러오는 중' : 'latest 결과 불러오기'}
          </Button>
        </div>
      </section>

      <div className="result-status-row">
        <span className={error ? 'error-text' : 'success-text'}>
          {error || loadStatus || 'OchestraResult 최신 결과를 기준으로 표시합니다.'}
        </span>
      </div>

      <div className="summary-grid result-summary-grid">
        {summary.map((item) => (
          <div className="summary-item" key={item.label}>
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </div>
        ))}
      </div>

      <section className="timeline-list" aria-label="에이전트 타임라인">
        {timelineSteps.length > 0 ? (
          timelineSteps.map((step, index) => (
            <TimelineCard index={index} step={step} key={step.key} />
          ))
        ) : (
          <div className="empty-state">
            <strong>아직 표시할 실행 결과가 없습니다.</strong>
            <span>latest 결과를 불러오면 에이전트별 판단 흐름이 타임라인으로 표시됩니다.</span>
          </div>
        )}
      </section>
    </section>
  );
}

function TimelineCard({ step, index }: { step: TimelineStep; index: number }) {
  const lines = [
    ...step.received,
    ...step.reasoning,
    ...step.result,
    step.handoff,
  ].filter(Boolean);

  return (
    <article className="timeline-card" style={{ animationDelay: `${index * 120}ms` }}>
      <div className="timeline-marker">
        <span>{index + 1}</span>
      </div>
      <div className="timeline-content">
        <div className="timeline-header">
          <div>
            <h3>{step.title}</h3>
            <span>{step.agent}</span>
          </div>
          <strong className={step.status === 'ok' ? 'status-ok' : 'status-muted'}>{step.status}</strong>
        </div>

        <div className="timeline-highlights">
          {step.highlights.map((item) => (
            <div key={item.label}>
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </div>
          ))}
        </div>

        <div className="timeline-message">
          {lines.slice(0, 8).map((line, lineIndex) => (
            <p key={`${step.key}-${lineIndex}`}>{line}</p>
          ))}
        </div>
      </div>
    </article>
  );
}

function DevView({
  summary,
  dataFlows,
}: {
  summary: Array<{ label: string; value: string }>;
  dataFlows: AgentDataFlow[];
}) {
  const stageResponseFiles = dataFlows.flatMap((flow) =>
    [...flow.received, ...flow.produced]
      .filter(isStageResponseFile)
      .map((file) => ({
        ...file,
        label: `${flow.agent}/stage_response.json`,
      })),
  );
  const visibleDataFlows = dataFlows.map((flow) => ({
    ...flow,
    received: flow.received.filter((file) => !isStageResponseFile(file)),
    produced: flow.produced.filter((file) => !isStageResponseFile(file)),
  }));

  return (
    <section className="result-view">
      <div className="summary-grid">
        {summary.map((item) => (
          <div className="summary-item" key={item.label}>
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </div>
        ))}
      </div>

      <section className="dev-flow-list" aria-label="에이전트 데이터 흐름">
        {visibleDataFlows.length > 0 ? (
          <>
            <OrchestratorFlowCard summary={summary} agentCount={visibleDataFlows.length} />
            {visibleDataFlows.map((flow, index) => <AgentFlowCard flow={flow} index={index} key={flow.key} />)}
          </>
        ) : (
          <div className="empty-state">
            <strong>아직 표시할 실행 결과가 없습니다.</strong>
            <span>OchestraResult 최신 파일을 불러오면 각 에이전트가 실제로 받은 파일과 생성한 파일이 단계별로 표시됩니다.</span>
          </div>
        )}
      </section>

      <section className="stage-response-panel" aria-label="stage response files">
        <div className="panel-header">
          <div>
            <h2>Stage responses</h2>
            <p className="panel-subtitle">각 단계의 wrapper 응답은 여기에서만 모아서 확인합니다.</p>
          </div>
          <span className="status-pill">{stageResponseFiles.length} files</span>
        </div>
        <FileList title="stage_response.json 모음" files={stageResponseFiles} />
      </section>
    </section>
  );
}

function OrchestratorFlowCard({
  summary,
  agentCount,
}: {
  summary: Array<{ label: string; value: string }>;
  agentCount: number;
}) {
  const mode = summary.find((item) => item.label === 'Mode')?.value || '-';

  return (
    <article className="orchestrator-flow-card">
      <div className="orchestrator-node">
        <div className="stage-index">AI</div>
        <div>
          <h3>오케스트레이션 AGENT</h3>
          <span>orchestrator_agent</span>
        </div>
      </div>
      <div className="orchestrator-message">
        <strong>오케스트레이션 AGENT가 에이전트들을 조율중입니다.</strong>
        <p>
          실행 요청을 해석하고, 현재 모드에 맞춰 취약점 수집부터 패치 전략까지 필요한 에이전트 순서를 결정합니다.
          각 에이전트가 만든 JSON 결과를 받아 다음 단계 입력으로 넘기고, 마지막에는 화면에서 볼 수 있도록 latest 결과를 저장합니다.
        </p>
      </div>
      <div className="orchestrator-meta">
        <span>Mode</span>
        <strong>{mode}</strong>
        <span>Agents</span>
        <strong>{agentCount}개</strong>
      </div>
    </article>
  );
}

function AgentFlowCard({ flow, index }: { flow: AgentDataFlow; index: number }) {
  return (
    <article className="dev-flow-card">
      <div className="dev-file-column">
        <FileList title="받은 파일" files={flow.received} />
      </div>
      <div className="dev-agent-node">
        <div className="stage-index">{index + 1}</div>
        <div>
          <h3>{flow.title}</h3>
          <span>{flow.agent}</span>
        </div>
        <strong className={flow.status === 'ok' ? 'status-ok' : 'status-muted'}>{flow.status}</strong>
      </div>
      <div className="dev-file-column">
        {flow.agent === 'vuln_collector_agent' ? (
          <VulnerabilityOutputFlow files={flow.produced} />
        ) : (
          <FileList title="내보낸 파일" files={flow.produced} />
        )}
      </div>
    </article>
  );
}

function VulnerabilityOutputFlow({ files }: { files: DataFile[] }) {
  const rawFile = findDataFile(files, 'focused_selected_raw_cves.json');
  const derivedFiles = [
    findDataFile(files, 'asset_matching_payload.json'),
    findDataFile(files, 'risk_assessment_payloads.json'),
    findDataFile(files, 'operational_impact_payloads.json'),
  ].filter((file): file is DataFile => Boolean(file));
  const groupedFiles = [rawFile, ...derivedFiles].filter((file): file is DataFile => Boolean(file));
  const extraFiles = files.filter((file) => !groupedFiles.includes(file));

  if (!rawFile || derivedFiles.length === 0) {
    return <FileList title="내보낸 파일" files={files} />;
  }

  return (
    <section className="handoff-block vuln-transform-flow">
      <h4>내보낸 파일</h4>
      <div className="raw-file-node">
        <FileToggleCard file={rawFile} />
      </div>
      <div className="transform-arrow" aria-hidden="true">
        <span />
      </div>
      <div className="derived-file-grid">
        {derivedFiles.map((file) => (
          <FileToggleCard file={file} key={`${file.path}:${file.label}`} />
        ))}
      </div>
      {extraFiles.length > 0 ? (
        <div className="extra-file-group">
          <span>추가 파일</span>
          {extraFiles.map((file) => (
            <FileToggleCard file={file} key={`${file.path}:${file.label}`} />
          ))}
        </div>
      ) : null}
    </section>
  );
}

function FileList({ title, files }: { title: string; files: DataFile[] }) {
  return (
    <section className="handoff-block">
      <h4>{title}</h4>
      {files.length > 0 ? (
        <div className="file-toggle-list">
          {files.map((file) => (
            <FileToggleCard file={file} key={`${file.path}:${file.label}`} />
          ))}
        </div>
      ) : (
        <div className="empty-file-pill">(not available)</div>
      )}
    </section>
  );
}

function FileToggleCard({ file }: { file: DataFile }) {
  return (
    <details className="file-toggle-card">
      <summary>
        <strong>{file.label}</strong>
        <span>{file.path}</span>
      </summary>
      <pre>{formatUnknownDataBlock(file.value)}</pre>
    </details>
  );
}

function findDataFile(files: DataFile[], filename: string): DataFile | undefined {
  return files.find((file) => file.label === filename || file.path.endsWith(`/${filename}`) || file.path.endsWith(`\\${filename}`));
}

function isStageResponseFile(file: DataFile): boolean {
  return file.label.endsWith('stage_response.json') || file.path.endsWith('/stage_response.json');
}

async function fetchLatestBundle(): Promise<unknown | null> {
  const response = await fetch('/api/local-results/latest', { cache: 'no-store' });
  return response.ok ? response.json() as Promise<unknown> : null;
}

function getRunButtonLabel(runState: RunState): string {
  if (runState === 'running') return '실행 중...';
  if (runState === 'success') return '실행 완료';
  if (runState === 'error') return '다시 실행';
  return '실행 시작';
}

function getBlockedRunReason(form: PipelineForm): string {
  if (form.mode === 'full') {
    return 'Full 실행은 실제 패치 실행 단계까지 이어질 수 있어 버튼에서는 차단했습니다. 안전 모드로 먼저 실행해 주세요.';
  }

  if (form.mode === 'patch_exec_only') {
    return 'Patch execution 단독 실행은 실제 변경 가능성이 있어 버튼에서 바로 실행하지 않습니다.';
  }

  if (form.mode === 'test' && form.stop_stage === 'patch_execution') {
    return 'Test 모드에서도 patch_execution 단계는 안전상 버튼 실행을 막아두었습니다.';
  }

  return '';
}

function getRunTargetStages(form: PipelineForm): StageKey[] {
  if (form.mode === 'vuln_only') return ['vuln'];
  if (form.mode === 'asset_only') return ['asset'];
  if (form.mode === 'risk_only') return ['risk'];
  if (form.mode === 'patch_only') return ['patch'];
  if (form.mode === 'before_exec') return ['vuln', 'asset', 'risk', 'patch'];
  if (form.mode === 'test') {
    const stopStage = form.stop_stage || 'patch';
    const stopIndex = stageOrder.indexOf(stopStage);
    return stopIndex >= 0 ? stageOrder.slice(0, stopIndex + 1) : ['vuln', 'asset', 'risk', 'patch'];
  }

  return [];
}

function getVisualStageState(
  form: PipelineForm,
  stageKey: StopStage,
  runState: RunState,
  runningStageKey: StageKey | null,
  runTargetStages: StageKey[],
  completedStageKeys: StageKey[],
): StageState {
  if (!stageKey) return 'ready';

  if (completedStageKeys.includes(stageKey)) {
    return 'done';
  }

  if (runState === 'running') {
    if (runningStageKey === stageKey) return 'running';
    if (runTargetStages.includes(stageKey)) return 'pending';
  }

  return getStageState(form, stageKey);
}

function getCompletedStages(summary: unknown): StageKey[] {
  if (!summary || typeof summary !== 'object') return [];

  const record = summary as Record<string, unknown>;
  const rawStages = Array.isArray(record.stages)
    ? record.stages
    : Array.isArray(record.executed_stages)
      ? record.executed_stages
      : Array.isArray(record.completed_stages)
        ? record.completed_stages
        : Array.isArray(record.pipeline)
          ? record.pipeline
          : getSavedAgentNames(record.saved_agent_dirs);

  return Array.from(new Set(rawStages
    .map((stage) => normalizeStageKey(String(stage)))
    .filter((stage): stage is StageKey => Boolean(stage))));
}

function extractLatestSummary(bundle: unknown): unknown {
  if (!bundle || typeof bundle !== 'object') return null;

  const root = bundle as Record<string, unknown>;
  const agents = root.agents;
  if (!agents || typeof agents !== 'object') return null;

  const orchestrator = (agents as Record<string, unknown>).orchestrator_agent;
  if (!orchestrator || typeof orchestrator !== 'object') return null;

  const files = (orchestrator as Record<string, unknown>).files;
  if (!files || typeof files !== 'object') return null;

  const summary = (files as Record<string, unknown>)['summary.json'];
  if (!summary || typeof summary !== 'object') return null;

  return (summary as Record<string, unknown>).value ?? null;
}

function getSummaryRunTag(summary: unknown): string {
  if (!summary || typeof summary !== 'object') return '';
  const runTag = (summary as Record<string, unknown>).run_tag;
  return typeof runTag === 'string' ? runTag : '';
}

function formatLatestCreatedAt(bundle: unknown): string {
  const runTag = getSummaryRunTag(extractLatestSummary(bundle));
  const createdAt = parseRunTagDate(runTag);

  if (createdAt) {
    return `이것은 ${createdAt}에 생성된 파일입니다.`;
  }

  if (bundle && typeof bundle === 'object') {
    const loadedAt = (bundle as Record<string, unknown>).loaded_at;
    if (typeof loadedAt === 'string') {
      return `이것은 ${formatIsoDateTime(loadedAt)}에 불러온 파일입니다.`;
    }
  }

  return '생성 시각을 확인하지 못했습니다.';
}

function parseRunTagDate(runTag: string): string {
  const match = runTag.match(/^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/);
  if (!match) return '';

  const [, year, month, day, hour, minute, second] = match;
  return `${year}-${month}-${day} ${hour}:${minute}:${second}`;
}

function formatIsoDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  const pad = (item: number) => String(item).padStart(2, '0');
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate()),
  ].join('-') + ` ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function getSavedAgentNames(value: unknown): string[] {
  if (!value || typeof value !== 'object') return [];

  return Object.entries(value as Record<string, unknown>)
    .filter(([, path]) => Boolean(path))
    .map(([agent]) => agent);
}

function normalizeStageKey(value: string): StageKey | null {
  const normalized = value.toLowerCase();

  if (normalized.includes('vuln')) return 'vuln';
  if (normalized.includes('asset') || normalized.includes('infra')) return 'asset';
  if (normalized.includes('risk')) return 'risk';
  if (normalized.includes('patch_execution') || normalized.includes('execution')) return 'patch_execution';
  if (normalized.includes('patch')) return 'patch';

  return null;
}

function parseResultJson(value: string): { value: unknown | null; error: string } {
  if (!value.trim()) return { value: null, error: '' };

  try {
    return { value: JSON.parse(value) as unknown, error: '' };
  } catch {
    return { value: null, error: 'JSON 형식이 올바르지 않습니다.' };
  }
}

function getViewFromPath(): View {
  if (window.location.pathname === '/result') return 'result';
  if (window.location.pathname === '/dev') return 'dev';
  return 'workflow';
}

export default App;
