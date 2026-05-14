export type PipelineMode =
  | 'full'
  | 'vuln_only'
  | 'asset_only'
  | 'risk_only'
  | 'patch_only'
  | 'before_exec'
  | 'patch_exec_only'
  | 'test';

export type StopStage =
  | ''
  | 'vuln'
  | 'asset'
  | 'risk'
  | 'patch'
  | 'patch_execution';

export type PipelineForm = {
  mode: PipelineMode;
  stack_name: string;
  region: string;
  cve_ids: string;
  stop_stage: StopStage;
  allow_followup: boolean;
  infra_matching_runtime_arn: string;
  patch_impact_runtime_arn: string;
  patch_execution_runtime_arn: string;
  payloadJson: string;
};

export type StageState = 'ready' | 'pending' | 'running' | 'done' | 'blocked';

export type Stage = {
  key: StopStage;
  title: string;
  agent: string;
  description: string;
  outputs: string[];
};

export type AgentDataFlow = {
  key: Exclude<StopStage, ''>;
  title: string;
  agent: string;
  status: string;
  received: DataFile[];
  produced: DataFile[];
};

export type DataFile = {
  label: string;
  path: string;
  value: unknown;
};

export type TimelineStep = {
  key: Exclude<StopStage, ''>;
  title: string;
  agent: string;
  status: string;
  received: string[];
  reasoning: string[];
  result: string[];
  handoff: string;
  highlights: Array<{
    label: string;
    value: string;
  }>;
};
