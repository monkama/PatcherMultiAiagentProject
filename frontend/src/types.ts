export type PipelineMode =
  | 'full'
  | 'vuln_only'
  | 'asset_only'
  | 'risk_only'
  | 'patch_only'
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

export type StageState = 'ready' | 'pending' | 'done' | 'blocked';

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
  received: Record<string, unknown>;
  produced: Record<string, unknown>;
};
