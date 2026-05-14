import { useMemo, useState } from 'react';
import { Button } from '@wanteddev/wds';
import { IconCopy } from '@wanteddev/wds-icon';
import { buildPayload, defaultForm, getStageState, prettyJson, stages } from './pipeline';
import type { PipelineForm, PipelineMode, StopStage } from './types';

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
  const [resultJson, setResultJson] = useState('');
  const [copyStatus, setCopyStatus] = useState('');

  const payload = useMemo(() => {
    try {
      return { value: buildPayload(form), error: '' };
    } catch (error) {
      return {
        value: null,
        error: error instanceof Error ? error.message : 'payload를 만들 수 없습니다.',
      };
    }
  }, [form]);

  const summary = useMemo(() => summarizeResult(resultJson), [resultJson]);

  const updateForm = <K extends keyof PipelineForm>(key: K, value: PipelineForm[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const copyPayload = async () => {
    if (!payload.value) return;
    await navigator.clipboard.writeText(prettyJson(payload.value));
    setCopyStatus('복사됨');
    window.setTimeout(() => setCopyStatus(''), 1600);
  };

  return (
    <main className="app-shell">
      <section className="topbar">
        <div>
          <p className="eyebrow">Patcher Multi AI Agent</p>
          <h1>보안 패치 오케스트레이션 콘솔</h1>
        </div>
        <div className="topbar-actions">
          <a className="ghost-button" href="../README.md">
            README
          </a>
          <Button
            type="button"
            variant="solid"
            color="primary"
            size="medium"
            leadingContent={<IconCopy />}
            onClick={copyPayload}
            disabled={!payload.value}
          >
            Payload 복사
          </Button>
        </div>
      </section>

      <section className="workspace-grid">
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
            <h2>파이프라인</h2>
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

        <section className="json-panel" aria-label="payload 미리보기">
          <div className="panel-header">
            <h2>Payload</h2>
            <span className={payload.error ? 'error-text' : 'success-text'}>
              {payload.error || copyStatus || '준비됨'}
            </span>
          </div>
          <textarea
            className="json-editor"
            value={form.payloadJson}
            onChange={(event) => updateForm('payloadJson', event.target.value)}
            spellCheck={false}
            aria-label="추가 payload JSON"
          />
          <pre className="json-preview">{payload.value ? prettyJson(payload.value) : payload.error}</pre>
        </section>

        <section className="result-panel" aria-label="결과 검토">
          <div className="panel-header">
            <h2>결과 검토</h2>
            <span className="muted-text">pipeline_result.json 붙여넣기</span>
          </div>
          <textarea
            className="result-editor"
            value={resultJson}
            onChange={(event) => setResultJson(event.target.value)}
            spellCheck={false}
            placeholder="{ ... }"
            aria-label="pipeline result JSON"
          />
          <div className="summary-grid">
            {summary.map((item) => (
              <div className="summary-item" key={item.label}>
                <span>{item.label}</span>
                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
        </section>
      </section>
    </main>
  );
}

function summarizeResult(value: string): Array<{ label: string; value: string }> {
  if (!value.trim()) {
    return [
      { label: 'Mode', value: '-' },
      { label: 'Pipeline', value: '-' },
      { label: 'Status', value: '대기' },
    ];
  }

  try {
    const parsed = JSON.parse(value) as {
      mode?: string;
      pipeline?: string[];
      agent_message?: string;
    };

    return [
      { label: 'Mode', value: parsed.mode || '-' },
      { label: 'Pipeline', value: parsed.pipeline?.length ? `${parsed.pipeline.length} stages` : '-' },
      { label: 'Status', value: parsed.agent_message || '분석됨' },
    ];
  } catch {
    return [
      { label: 'Mode', value: '-' },
      { label: 'Pipeline', value: '-' },
      { label: 'Status', value: 'JSON 오류' },
    ];
  }
}

export default App;
