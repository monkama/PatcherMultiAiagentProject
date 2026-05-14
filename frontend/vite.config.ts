import { spawn } from 'node:child_process';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import type { IncomingMessage } from 'node:http';
import { resolve } from 'node:path';
import { defineConfig, loadEnv, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';

type RunForm = {
  mode?: string;
  stack_name?: string;
  region?: string;
  cve_ids?: string;
  stop_stage?: string;
  allow_followup?: boolean;
  infra_matching_runtime_arn?: string;
  patch_impact_runtime_arn?: string;
  patch_execution_runtime_arn?: string;
};

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiTarget = env.VITE_API_PROXY_TARGET;

  return {
    plugins: [react(), localResultPlugin()],
    server: {
      port: 5173,
      proxy: apiTarget
        ? {
            '/api': {
              target: apiTarget,
              changeOrigin: true,
              secure: false,
            },
          }
        : undefined,
    },
  };
});

function localResultPlugin(): Plugin {
  return {
    name: 'local-orchestrator-result',
    configureServer(server) {
      server.middlewares.use('/api/local-results/latest', async (_request, response) => {
        const resultRoot = resolve(process.cwd(), '../MultiAIagent/OchestraResult');

        try {
          const bundle = await readLatestResultBundle(resultRoot);
          response.setHeader('Content-Type', 'application/json; charset=utf-8');
          response.end(JSON.stringify(bundle, null, 2));
        } catch {
          response.statusCode = 404;
          response.setHeader('Content-Type', 'application/json; charset=utf-8');
          response.end(JSON.stringify({ message: 'OchestraResult latest 파일을 찾을 수 없습니다.' }));
        }
      });

      server.middlewares.use('/api/run-orchestrator', async (request, response) => {
        if (request.method !== 'POST') {
          response.statusCode = 405;
          response.setHeader('Content-Type', 'application/json; charset=utf-8');
          response.end(JSON.stringify({ error: 'POST method only' }));
          return;
        }

        try {
          const body = await readJsonBody(request);
          const form = (body.form ?? body) as RunForm;
          const blockReason = getBlockedRunReason(form);

          if (blockReason) {
            response.statusCode = 400;
            response.setHeader('Content-Type', 'application/json; charset=utf-8');
            response.end(JSON.stringify({ error: blockReason }));
            return;
          }

          const repoRoot = resolve(process.cwd(), '..');
          const resultRoot = resolve(repoRoot, 'MultiAIagent/OchestraResult');
          const runResult = await runOrchestrator(repoRoot, form);
          const bundle = await readLatestResultBundle(resultRoot);
          const summary = await readJsonIfExists(resolve(resultRoot, 'orchestrator_agent/latest/summary.json'));
          const errorMessage = runResult.code === 0
            ? undefined
            : runResult.stderr.slice(-1200) || runResult.stdout.slice(-1200) || '오케스트레이터 실행이 저장 전에 실패했습니다.';

          await writeRunDiagnostic(resultRoot, {
            status: runResult.code === 0 ? 'success' : 'failed',
            form,
            summary,
            stdout: runResult.stdout.slice(-8000),
            stderr: runResult.stderr.slice(-8000),
            error: errorMessage,
          });

          response.statusCode = runResult.code === 0 ? 200 : 500;
          response.setHeader('Content-Type', 'application/json; charset=utf-8');
          response.end(JSON.stringify({
            message: runResult.code === 0 ? 'ok' : 'orchestrator failed',
            summary,
            bundle,
            stdout: runResult.stdout.slice(-4000),
            stderr: runResult.stderr.slice(-4000),
            error: errorMessage,
          }));
        } catch (error) {
          const resultRoot = resolve(process.cwd(), '../MultiAIagent/OchestraResult');
          await writeRunDiagnostic(resultRoot, {
            status: 'failed',
            error: error instanceof Error ? error.message : '오케스트레이터 실행 중 오류가 발생했습니다.',
          });
          response.statusCode = 500;
          response.setHeader('Content-Type', 'application/json; charset=utf-8');
          response.end(JSON.stringify({
            error: error instanceof Error ? error.message : '오케스트레이터 실행 중 오류가 발생했습니다.',
          }));
        }
      });
    },
  };
}

async function writeRunDiagnostic(resultRoot: string, diagnostic: Record<string, unknown>) {
  const payload = {
    ...diagnostic,
    generated_at: new Date().toISOString(),
  };
  const latestDir = resolve(resultRoot, 'frontend_run/latest');
  const runDir = resolve(resultRoot, `frontend_run/${new Date().toISOString().replace(/[:.]/g, '-')}`);

  await mkdir(latestDir, { recursive: true });
  await mkdir(runDir, { recursive: true });
  await writeFile(resolve(latestDir, 'run_diagnostic.json'), JSON.stringify(payload, null, 2), 'utf-8');
  await writeFile(resolve(runDir, 'run_diagnostic.json'), JSON.stringify(payload, null, 2), 'utf-8');
}

function readJsonBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolveBody, reject) => {
    let body = '';

    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      body += chunk;
    });
    request.on('end', () => {
      try {
        resolveBody(body ? JSON.parse(body) as Record<string, unknown> : {});
      } catch (error) {
        reject(error);
      }
    });
    request.on('error', reject);
  });
}

async function runOrchestrator(repoRoot: string, form: RunForm) {
  const pythonPath = resolve(repoRoot, '.venv/Scripts/python.exe');
  const scriptPath = resolve(repoRoot, 'MultiAIagent/run_orchestrator_runtime.py');
  const env = await buildRunEnv(repoRoot, form);

  if (form.mode === 'before_exec') {
    return runOrchestratorWithPayload(repoRoot, pythonPath, env, buildBeforeExecPayload(form));
  }

  const input = buildInteractiveInput(form);

  return new Promise<{ code: number; stdout: string; stderr: string }>((resolveRun, reject) => {
    const child = spawn(pythonPath, [scriptPath], {
      cwd: repoRoot,
      env,
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk);
    });
    child.on('error', reject);
    child.on('close', (code) => {
      resolveRun({ code: code ?? 1, stdout, stderr });
    });

    child.stdin.write(input);
    child.stdin.end();
  });
}

function runOrchestratorWithPayload(
  repoRoot: string,
  pythonPath: string,
  env: NodeJS.ProcessEnv,
  payload: Record<string, unknown>,
) {
  const code = [
    'import json, sys',
    'from pathlib import Path',
    'repo_root = Path.cwd()',
    'sys.path.insert(0, str(repo_root / "MultiAIagent"))',
    'import run_orchestrator_runtime as runner',
    'runner._load_env()',
    'runner._refresh_runtime_defaults()',
    'runner.RESULT_ROOT.mkdir(parents=True, exist_ok=True)',
    'runtime_arn = runner._require_runtime_arn(runner.DEFAULT_ORCHESTRATOR_ARN.strip(), "오케스트라 런타임 ARN", runner.ORCHESTRATOR_RUNTIME_ARN_ENV_KEYS)',
    'payload = json.loads(sys.stdin.read())',
    'result, invoke_meta = runner._invoke_orchestrator(runtime_arn, payload.get("region") or runner.DEFAULT_REGION, payload)',
    'summary = runner._save_result_bundle(result, payload, invoke_meta)',
    'print(json.dumps({"summary": summary, "invoke_meta": invoke_meta}, ensure_ascii=False))',
  ].join('\n');

  return new Promise<{ code: number; stdout: string; stderr: string }>((resolveRun, reject) => {
    const child = spawn(pythonPath, ['-c', code], {
      cwd: repoRoot,
      env,
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk);
    });
    child.on('error', reject);
    child.on('close', (exitCode) => {
      resolveRun({ code: exitCode ?? 1, stdout, stderr });
    });

    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

function buildBeforeExecPayload(form: RunForm): Record<string, unknown> {
  return {
    mode: 'test',
    stop_stage: 'patch',
    region: form.region || 'ap-northeast-2',
    stack_name: form.stack_name || 'megathon',
    cve_ids: form.cve_ids || undefined,
    allow_followup: form.allow_followup ?? true,
  };
}

async function buildRunEnv(repoRoot: string, form: RunForm): Promise<NodeJS.ProcessEnv> {
  const fileEnv = await readDotEnv(resolve(repoRoot, 'MultiAIagent/.env'));
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...fileEnv,
    AWS_EC2_METADATA_DISABLED: 'true',
    PYTHONUTF8: '1',
  };

  setArnEnv(env, 'ORCHESTRATOR_AGENTCORE_ARN', fileEnv.ORCHESTRATOR_AGENTCORE_ARN || fileEnv.ORCHESTRATOR_ARN);
  setArnEnv(env, 'INFRA_MATCHING_AGENTCORE_ARN', form.infra_matching_runtime_arn || fileEnv.INFRA_MATCHING_AGENTCORE_ARN || fileEnv.ASSET_MATCHING_AGENTCORE_ARN);
  setArnEnv(env, 'ASSET_MATCHING_AGENTCORE_ARN', form.infra_matching_runtime_arn || fileEnv.ASSET_MATCHING_AGENTCORE_ARN || fileEnv.INFRA_MATCHING_AGENTCORE_ARN);
  setArnEnv(env, 'PATCH_IMPACT_AGENTCORE_ARN', form.patch_impact_runtime_arn || fileEnv.PATCH_IMPACT_AGENTCORE_ARN || fileEnv.PATCH_IMPACT_ARN);
  setArnEnv(env, 'PATCH_EXECUTION_AGENTCORE_ARN', form.patch_execution_runtime_arn || fileEnv.PATCH_EXECUTION_AGENTCORE_ARN || fileEnv.PATCH_EXECUTION_ARN);

  return env;
}

async function readDotEnv(path: string): Promise<Record<string, string>> {
  try {
    const text = await readFile(path, 'utf-8');
    const values: Record<string, string> = {};

    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      const index = trimmed.indexOf('=');
      if (index < 0) continue;

      const key = trimmed.slice(0, index).trim();
      const value = trimmed.slice(index + 1).trim().replace(/^['"]|['"]$/g, '');
      values[key] = value;
    }

    return values;
  } catch {
    return {};
  }
}

function setArnEnv(env: NodeJS.ProcessEnv, key: string, value?: string) {
  if (!value) return;

  const normalizedValue = normalizeRuntimeArn(value);
  env[key] = normalizedValue;
  env[key.replace('_AGENTCORE_ARN', '_ARN')] = normalizedValue;
}

function normalizeRuntimeArn(value: string): string {
  return value.trim().replace(/\/runtime-endpoint\/[^/]+$/i, '');
}

function buildInteractiveInput(form: RunForm): string {
  const mode = form.mode || 'patch_only';
  const lines = [
    getModeNumber(mode),
    form.region || '',
    form.stack_name || '',
  ];

  if (mode === 'vuln_only') {
    lines.push(form.cve_ids || '');
  } else if (mode === 'asset_only') {
    lines.push('');
  } else if (mode === 'risk_only') {
    lines.push('', '');
  } else if (mode === 'patch_only') {
    lines.push(form.patch_impact_runtime_arn || '', form.infra_matching_runtime_arn || '', '', '', '');
  } else if (mode === 'before_exec') {
    lines[0] = '7';
    lines.push('4');
    appendStopStageInputs(lines, 'patch', form);
  } else if (mode === 'test') {
    const stopStage = form.stop_stage || 'patch';
    lines.push(getStopStageNumber(stopStage));
    appendStopStageInputs(lines, stopStage, form);
  }

  lines.push('y');
  return `${lines.join('\n')}\n`;
}

function appendStopStageInputs(lines: string[], stopStage: string, form: RunForm) {
  if (stopStage === 'vuln') {
    lines.push(form.cve_ids || '');
  } else if (stopStage === 'asset') {
    lines.push('');
  } else if (stopStage === 'risk') {
    lines.push('', '');
  } else {
    lines.push(form.patch_impact_runtime_arn || '', form.infra_matching_runtime_arn || '', '', '', '');
  }
}

function getModeNumber(mode: string): string {
  const modeNumbers: Record<string, string> = {
    vuln_only: '2',
    asset_only: '3',
    risk_only: '4',
    patch_only: '5',
    before_exec: '7',
    test: '7',
  };

  return modeNumbers[mode] || '5';
}

function getStopStageNumber(stopStage: string): string {
  const stageNumbers: Record<string, string> = {
    vuln: '1',
    asset: '2',
    risk: '3',
    patch: '4',
  };

  return stageNumbers[stopStage] || '4';
}

function getBlockedRunReason(form: RunForm): string {
  if (form.mode === 'full') return 'Full 실행은 버튼에서 차단했습니다.';
  if (form.mode === 'patch_exec_only') return 'Patch execution 실행은 버튼에서 차단했습니다.';
  if (form.mode === 'test' && form.stop_stage === 'patch_execution') return 'Patch execution 단계는 버튼에서 차단했습니다.';
  return '';
}

async function readJsonIfExists(path: string): Promise<unknown | null> {
  try {
    return JSON.parse(await readFile(path, 'utf-8')) as unknown;
  } catch {
    return null;
  }
}

async function readLatestResultBundle(resultRoot: string) {
  const agents: Record<string, unknown> = {};
  const entries = await readdir(resultRoot, { withFileTypes: true });

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;

    const agentName = entry.name;
    const latestDir = resolve(resultRoot, agentName, 'latest');
    const files: Record<string, unknown> = {};

    try {
      const latestEntries = await readdir(latestDir, { withFileTypes: true });

      for (const latestEntry of latestEntries) {
        if (!latestEntry.isFile() || !latestEntry.name.endsWith('.json')) continue;

        const filePath = resolve(latestDir, latestEntry.name);
        const relativePath = `MultiAIagent/OchestraResult/${agentName}/latest/${latestEntry.name}`;
        const text = await readFile(filePath, 'utf-8');

        try {
          files[latestEntry.name] = {
            path: relativePath,
            value: JSON.parse(text) as unknown,
          };
        } catch {
          files[latestEntry.name] = {
            path: relativePath,
            value: text,
            parse_error: true,
          };
        }
      }
    } catch {
      // An agent may not have a latest directory yet.
    }

    agents[agentName] = {
      latest_path: `MultiAIagent/OchestraResult/${agentName}/latest`,
      files,
    };
  }

  return {
    source: 'OchestraResult latest files',
    loaded_at: new Date().toISOString(),
    agents,
  };
}
