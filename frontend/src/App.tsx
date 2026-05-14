import { useEffect, useMemo, useState } from 'react';
import { Button } from '@wanteddev/wds';
import { IconCopy } from '@wanteddev/wds-icon';
import {
  buildAgentDataFlows,
  defaultForm,
  formatDataBlock,
  getStageState,
  stages,
  summarizePipelineResult,
} from './pipeline';
import type { AgentDataFlow, PipelineForm, PipelineMode, StopStage } from './types';

type View = 'workflow' | 'result';

const modeOptions: Array<{ value: PipelineMode; label: string }> = [
  { value: 'full', label: 'Full' },
  { value: 'vuln_only', label: 'Vuln' },
  { value: 'asset_only', label: 'Asset' },
  { value: 'risk_only', label: 'Risk' },
  { value: 'patch_only', label: 'Patch' },
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

function App() {
  const [form, setForm] = useState<PipelineForm>(defaultForm);
  const [view, setView] = useState<View>(() => getViewFromPath());
  const [resultJson, setResultJson] = useState(() => localStorage.getItem('pipeline-result-json') || '');
  const [copyStatus, setCopyStatus] = useState('');

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
  const summary = useMemo(() => summarizePipelineResult(parsedResult.value), [parsedResult.value]);

  const updateForm = <K extends keyof PipelineForm>(key: K, value: PipelineForm[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const navigate = (nextView: View) => {
    const nextPath = nextView === 'result' ? '/result' : '/';
    window.history.pushState(null, '', nextPath);
    setView(nextView);
  };

  const copyResult = async () => {
    if (!resultJson.trim()) return;
    await navigator.clipboard.writeText(resultJson);
    setCopyStatus('복사됨');
    window.setTimeout(() => setCopyStatus(''), 1600);
  };

  const loadResultFile = async (file: File | undefined) => {
    if (!file) return;
    setResultJson(await file.text());
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
          </div>
          <a className="ghost-button" href="../README.md">
            README
          </a>
        </div>
      </section>

      {view === 'workflow' ? (
        <WorkflowView form={form} updateForm={updateForm} />
      ) : (
        <ResultView
          resultJson={resultJson}
          setResultJson={setResultJson}
          error={parsedResult.error}
          summary={summary}
          dataFlows={dataFlows}
          copyStatus={copyStatus}
          copyResult={copyResult}
          loadResultFile={loadResultFile}
        />
      )}
    </main>
  );
}

function WorkflowView({
  form,
  updateForm,
}: {
  form: PipelineForm;
  updateForm: <K extends keyof PipelineForm>(key: K, value: PipelineForm[K]) => void;
}) {
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

        <label className="toggle-field">
          <input
            type="checkbox"
            checked={form.allow_followup}
            onChange={(event) => updateForm('allow_followup', event.target.checked)}
          />
          <span>Patch 단계에서 asset follow-up 허용</span>
        </label>

        <details className="advanced-box">
          <summary>Runtime ARN</summary>
          <label className="field">
            <span>Infra matching ARN</span>
            <input
              value={form.infra_matching_runtime_arn}
              onChange={(event) => updateForm('infra_matching_runtime_arn', event.target.value)}
            />
          </label>
          <label className="field">
            <span>Patch impact ARN</span>
            <input
              value={form.patch_impact_runtime_arn}
              onChange={(event) => updateForm('patch_impact_runtime_arn', event.target.value)}
            />
          </label>
          <label className="field">
            <span>Patch execution ARN</span>
            <input
              value={form.patch_execution_runtime_arn}
              onChange={(event) => updateForm('patch_execution_runtime_arn', event.target.value)}
            />
          </label>
        </details>
      </aside>

      <section className="pipeline-panel" aria-label="파이프라인 단계">
        <div className="panel-header">
          <h2>워크플로우</h2>
          <span className="muted-text">기존 Python 실행 흐름 기준</span>
        </div>
        <div className="stage-list">
          {stages.map((stage, index) => {
            const state = getStageState(form, stage.key);
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

function ResultView({
  resultJson,
  setResultJson,
  error,
  summary,
  dataFlows,
  copyStatus,
  copyResult,
  loadResultFile,
}: {
  resultJson: string;
  setResultJson: (value: string) => void;
  error: string;
  summary: Array<{ label: string; value: string }>;
  dataFlows: AgentDataFlow[];
  copyStatus: string;
  copyResult: () => Promise<void>;
  loadResultFile: (file: File | undefined) => Promise<void>;
}) {
  return (
    <section className="result-view">
      <section className="result-input-panel" aria-label="결과 입력">
        <div className="panel-header">
          <div>
            <h2>실행 결과</h2>
            <p className="panel-subtitle">pipeline_result.json을 붙여넣거나 파일로 불러오세요.</p>
          </div>
          <div className="result-actions">
            <label className="file-button">
              파일 선택
              <input
                type="file"
                accept=".json,application/json"
                onChange={(event) => loadResultFile(event.target.files?.[0])}
              />
            </label>
            <Button
              type="button"
              variant="outlined"
              color="primary"
              size="medium"
              leadingContent={<IconCopy />}
              onClick={copyResult}
              disabled={!resultJson.trim()}
            >
              JSON 복사
            </Button>
          </div>
        </div>
        <textarea
          className="result-editor"
          value={resultJson}
          onChange={(event) => setResultJson(event.target.value)}
          spellCheck={false}
          placeholder="{ ... }"
          aria-label="pipeline result JSON"
        />
        <div className="result-status-row">
          <span className={error ? 'error-text' : 'success-text'}>
            {error || copyStatus || '결과 JSON을 기다리는 중'}
          </span>
        </div>
      </section>

      <div className="summary-grid">
        {summary.map((item) => (
          <div className="summary-item" key={item.label}>
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </div>
        ))}
      </div>

      <section className="flow-list" aria-label="에이전트 데이터 흐름">
        {dataFlows.length > 0 ? (
          dataFlows.map((flow, index) => <AgentFlowCard flow={flow} index={index} key={flow.key} />)
        ) : (
          <div className="empty-state">
            <strong>아직 표시할 실행 결과가 없습니다.</strong>
            <span>오케스트레이터 실행 후 생성된 pipeline_result.json을 붙여넣으면 각 에이전트의 입력과 출력이 단계별로 표시됩니다.</span>
          </div>
        )}
      </section>
    </section>
  );
}

function AgentFlowCard({ flow, index }: { flow: AgentDataFlow; index: number }) {
  return (
    <article className="flow-card">
      <div className="flow-header">
        <div className="stage-index">{index + 1}</div>
        <div>
          <h3>{flow.title}</h3>
          <span>{flow.agent}</span>
        </div>
        <strong className={flow.status === 'ok' ? 'status-ok' : 'status-muted'}>{flow.status}</strong>
      </div>
      <div className="handoff-grid">
        <JsonBlock title="받은 데이터" value={flow.received} />
        <JsonBlock title="내보낸 데이터" value={flow.produced} />
      </div>
    </article>
  );
}

function JsonBlock({ title, value }: { title: string; value: Record<string, unknown> }) {
  return (
    <section className="handoff-block">
      <h4>{title}</h4>
      <pre>{formatDataBlock(value)}</pre>
    </section>
  );
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
  return window.location.pathname === '/result' ? 'result' : 'workflow';
}

export default App;
