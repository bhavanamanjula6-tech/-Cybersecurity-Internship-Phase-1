import express from 'express';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import dotenv from 'dotenv';
import type { ViteDevServer } from 'vite';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import type { CopilotRouterOptions } from './src/server/ai/copilotRouter';

// Ensure TypeScript ESM execution:
// If invoked via bare `node server.ts` (such as in Cloud Run production container),
// re-execute with `--import tsx` so extensionless TypeScript module specifiers resolve properly.
const isTsxActive = Boolean(
  process.env.__TSX_BOOTSTRAPPED__ ||
  process.execArgv.some((arg) => arg.includes('tsx')) ||
  process.env.npm_lifecycle_script?.includes('tsx')
);

if (!isTsxActive && process.env.NODE_ENV !== 'test') {
  const { spawn } = await import('node:child_process');
  const child = spawn(process.execPath, ['--import', 'tsx', ...process.argv.slice(1)], {
    stdio: 'inherit',
    env: { ...process.env, __TSX_BOOTSTRAPPED__: '1' },
  });

  child.on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
    } else {
      process.exit(code ?? 0);
    }
  });

  const forwardSignal = (sig: NodeJS.Signals) => {
    if (!child.killed) {
      child.kill(sig);
    }
  };
  process.on('SIGTERM', () => forwardSignal('SIGTERM'));
  process.on('SIGINT', () => forwardSignal('SIGINT'));

  // Suspend this parent process while the bootstrapped child executes
  await new Promise(() => {});
}

/**
 * Determine the runtime port cleanly:
 * - In production (Cloud Run), the container injects PORT (typically 8080).
 * - In local development / AI Studio, NGINX is listening on NGINX_PORT (8080)
 *   and proxying to DEFAULT_APP_PORT (3000), so dev server must bind to 3000.
 * - Allows PORT_OVERRIDE for testing on alternate ports without conflicts.
 */
export function resolvePort(): number {
  if (process.env.PORT_OVERRIDE) {
    return Number(process.env.PORT_OVERRIDE);
  }
  if (process.env.NODE_ENV === 'production') {
    return Number(process.env.PORT) || 8080;
  }
  // In development, if NGINX_PORT is set and equals PORT, avoid colliding with nginx
  if (process.env.NGINX_PORT && process.env.PORT === process.env.NGINX_PORT) {
    return Number(process.env.DEFAULT_APP_PORT) || 3000;
  }
  return Number(process.env.PORT) || Number(process.env.DEFAULT_APP_PORT) || 3000;
}

export interface ServerInstance {
  app: express.Express;
  httpServer: http.Server;
  vite?: ViteDevServer;
  close: () => Promise<void>;
}

export interface CreateServerOptions {
  copilotOptions?: CopilotRouterOptions;
}

export async function createServer(options?: CreateServerOptions): Promise<ServerInstance> {
  const app = express();
  const httpServer = http.createServer(app);
  let viteDevServer: ViteDevServer | undefined;
  const isProd = process.env.NODE_ENV === 'production';

  // Basic request body parsing
  app.use(express.json());

  // Health check endpoint - always returns minimal JSON with HTTP 200
  app.get('/healthz', (_req, res) => {
    res.status(200).json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      environment: isProd ? 'production' : 'development',
    });
  });

  // Base API router
  const apiRouter = express.Router();
  apiRouter.get('/status', (_req, res) => {
    res.status(200).json({
      service: 'CyberOps SOC API',
      status: 'online',
      version: '1.0.0',
    });
  });

  // Mount AI Copilot router under /api/copilot
  const { createCopilotRouter } = await import('./src/server/ai/copilotRouter');
  const copilotRouter = createCopilotRouter(options?.copilotOptions);
  apiRouter.use('/copilot', copilotRouter);

  app.use('/api', apiRouter);

  // Catch-all for undefined API routes: ensures unknown API routes return 404 JSON
  // and are never accidentally swallowed by the SPA fallback
  app.all('/api/*', (_req, res) => {
    res.status(404).json({ error: 'API endpoint not found' });
  });

  // Frontend integration: Vite middleware in development, static assets in production
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    viteDevServer = await createViteServer({
      server: {
        middlewareMode: true,
        // Bind Vite's WebSocket handler directly to the shared HTTP server.
        // This allows browser HMR connections to use the standard preview port/path (WSS over 443 -> NGINX -> 3000)
        // rather than opening an inaccessible separate port (such as 24678).
        ws: { server: httpServer },
      },
      appType: 'spa',
    });
    app.use(viteDevServer.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    if (!fs.existsSync(distPath)) {
      console.warn('WARNING: dist/ directory not found. Please run "npm run build" to generate production assets.');
    }
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      const indexPath = path.resolve(distPath, 'index.html');
      if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
      } else {
        res.status(503).json({ error: 'Application build in progress or dist/ missing' });
      }
    });
  }

  // Global error handler - never leaks stack traces, secrets, or internal details
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const message = err instanceof Error ? err.message : 'Unknown error';
    console.error('Unhandled server error:', message);
    res.status(500).json({ error: 'Internal server error' });
  });

  const close = async (): Promise<void> => {
    if (viteDevServer) {
      await viteDevServer.close();
    }
    if (httpServer.listening) {
      await new Promise<void>((resolve, reject) => {
        httpServer.close((err) => (err ? reject(err) : resolve()));
      });
    }
  };

  return { app, httpServer, vite: viteDevServer, close };
}

export async function startServer(portOverride?: number): Promise<http.Server> {
  const isProd = process.env.NODE_ENV === 'production';
  const port = portOverride ?? resolvePort();
  const host = '0.0.0.0';

  try {
    const { httpServer, close } = await createServer();
    
    httpServer.listen(port, host, () => {
      console.log(`[CyberOps SOC] Server running on http://${host}:${port} (${isProd ? 'production' : 'development'})`);
    });

    httpServer.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`[CyberOps SOC] Port ${port} is already in use.`);
      } else {
        console.error('[CyberOps SOC] Server listen error:', err.message);
      }
      process.exit(1);
    });

    const shutdown = async (signal: string) => {
      console.log(`[CyberOps SOC] Received ${signal}, shutting down gracefully...`);
      await close();
      console.log('[CyberOps SOC] HTTP and WebSocket server closed.');
      process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

    return httpServer;
  } catch (error) {
    console.error('[CyberOps SOC] Fatal startup error:', error instanceof Error ? error.message : error);
    process.exit(1);
  }
}

// Start immediately when executed directly
const isDirectEntry = process.argv[1] && (
  path.resolve(process.argv[1]) === path.resolve(__filename) ||
  process.argv[1].endsWith('server.ts') ||
  process.argv[1].endsWith('server.js')
);

if (isDirectEntry && process.env.NODE_ENV !== 'test') {
  startServer();
}
