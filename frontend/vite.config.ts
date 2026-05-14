import { readdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { defineConfig, loadEnv, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';

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
    },
  };
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
