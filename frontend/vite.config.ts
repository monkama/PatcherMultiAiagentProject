import { readFile } from 'node:fs/promises';
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
        const resultPath = resolve(
          process.cwd(),
          '../MultiAIagent/OchestraResult/orchestrator_agent/latest/response.json',
        );

        try {
          const body = await readFile(resultPath, 'utf-8');
          response.setHeader('Content-Type', 'application/json; charset=utf-8');
          response.end(body);
        } catch {
          response.statusCode = 404;
          response.setHeader('Content-Type', 'application/json; charset=utf-8');
          response.end(JSON.stringify({ message: 'latest response.json을 찾을 수 없습니다.' }));
        }
      });
    },
  };
}
