import './config/database-url-bootstrap.js';
import { shutdownOpenTelemetrySdk } from './instrumentation.js';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import http from 'http';
import type { Socket } from 'node:net';
import webhookRouter from './routes/webhook.js';
import webhookGitLabRouter from './routes/webhook-gitlab.js';
import apiRouter from './routes/api.js';
import apiGitLabRouter from './routes/api-gitlab.js';
import adminReplayRouter from './routes/admin-replay.js';
import logger, { getLogsDirectory } from './utils/logger.js';
import { client } from './utils/metrics.js';
import './utils/neatcode-data-metrics-bootstrap.js';
import {
  startReconciliationCron,
  stopReconciliationCron,
} from './jobs/index-reconciliation-cron.js';
import {
  startWebhookEventsCleanupCron,
  stopWebhookEventsCleanupCron,
} from './jobs/webhook-events-cleanup-cron.js';
import { langfuse } from './services/langfuse.service.js';
import { initializeWebhookIntegrations } from './controllers/webhook/integration-init.js';
import { createOtelSpanRunner } from './utils/otel-span.js';
import { apiLimiter, webhookLimiter } from './middleware/rate-limiter.js';
import {
  errorHandler,
  notFoundHandler,
  requestIdMiddleware,
} from './middleware/error-handling/index.js';
import { getNeo4jClient } from '@hello-devzy/neatcode-data/backend';
import { repoMetadataRepository } from '@hello-devzy/neatcode-data';
const app = express();
const PORT = process.env.PORT || 8080;
type RawBodyRequest = express.Request & { rawBody?: Buffer };
const withOtelSpan = createOtelSpanRunner('neatcode-backend.server');
// Log startup info
logger.info('Starting server...', { logsDirectory: getLogsDirectory() });
await initializeWebhookIntegrations();
// Trust proxy (for production behind load balancers)
app.set('trust proxy', 1);
// Request ID middleware - attach unique ID to each request for tracing
// Must be before body parsers so parse errors also get a requestId
app.use(requestIdMiddleware);
// Middleware
app.use(
  cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  })
);
app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);
app.use(
  morgan('combined', {
    skip: (req) => req.url === '/metrics',
    stream: {
      write: (msg) => {
        const line = msg.trim();
        // Apache combined: ... "METHOD path HTTP/x" STATUS ...
        const statusMatch = line.match(/"\s(\d{3})\s/);
        const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
        const meta = { channel: 'http' as const };
        if (status >= 500) {
          logger.error(line, meta);
        } else if (status >= 400) {
          logger.warn(line, meta);
        } else {
          logger.info(line, meta);
        }
      },
    },
  })
);
// Webhook routes - with raw body capture for signature verification
// Rate limits failed webhook requests per IP (successful deliveries aren't counted)
// Normalize Content-Type for webhooks: body-parser@2.2 rejects "charset=UTF-8" (GitHub sends this).
// Strip charset param so express.json() accepts the payload.
app.use((req, res, next) => {
  const ct = req.headers['content-type'];
  if (typeof ct === 'string' && ct.includes('charset')) {
    const normalized = ct.replace(/;\s*charset=[^;]*/gi, '').trim();
    req.headers['content-type'] = normalized || 'application/json';
  }
  next();
});
// Helper middleware for raw body capture (needed by both GitHub and GitLab signature verification)
const rawBodyParser = express.json({
  limit: '1mb',
  verify: (req, _res, buf) => {
    (req as RawBodyRequest).rawBody = buf;
  },
});
// GitHub webhook route (new path)
app.use('/webhook/github', webhookLimiter, rawBodyParser, webhookRouter);
// GitLab webhook alias (must be before /webhook so /webhook/gitlab matches)
app.use('/webhook/gitlab', webhookLimiter, rawBodyParser, webhookGitLabRouter);
// Legacy webhook route (backward compatibility for existing GitHub App webhook configurations)
// Aliased to /webhooks/github
app.use('/webhook', webhookLimiter, rawBodyParser, webhookRouter);
// Regular JSON parsing for other routes
app.use(express.json({ limit: '1mb' }));
// Health check (liveness)
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});
// Readiness (for K8s/OpenShift; can later return 503 during graceful shutdown)
app.get('/ready', (req, res) => {
  res.status(200).json({ status: 'ready' });
});
// Prometheus metrics endpoint (must remain outside API rate limiter).
// Access control: bearer token when METRICS_TOKEN is set, localhost-only otherwise.
const METRICS_TOKEN = process.env.METRICS_TOKEN?.trim() || '';
const LOCALHOST = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
app.get('/metrics', async (req, res) => {
  if (METRICS_TOKEN) {
    const auth = req.headers['authorization'] ?? '';
    if (auth !== `Bearer ${METRICS_TOKEN}`) {
      res.status(403).end();
      return;
    }
  } else {
    const ip = req.socket.remoteAddress ?? '';
    if (!LOCALHOST.has(ip)) {
      res.status(403).end();
      return;
    }
  }
  res.set('Content-Type', client.register.contentType);
  res.end(await client.register.metrics());
});
// Apply general API rate limiter and mount API routers
// The routers handle server-to-server endpoints (protected by X-Internal-Secret)
app.use('/api', apiLimiter, apiRouter);
app.use('/api/gitlab', apiLimiter, apiGitLabRouter);
app.use('/api/internal/webhook', apiLimiter, adminReplayRouter);
// 404 handler - catches unmatched routes and forwards to error handler
app.use(notFoundHandler);
// Centralized error handler - MUST be 4-arity (err, req, res, next)
// This catches all errors from routes and middleware
app.use(errorHandler);
// Create HTTP server for graceful shutdown support
const server = http.createServer(app);
// Track open TCP connections (keep-alive sockets can otherwise block server.close)
const activeConnections = new Set<Socket>();
server.on('connection', (socket) => {
  activeConnections.add(socket);
  socket.on('close', () => {
    activeConnections.delete(socket);
  });
});
// Track if shutdown is in progress to prevent multiple shutdown attempts
let isShuttingDown = false;
/**
 * Graceful shutdown handler
 * Ensures all connections are properly closed before exiting
 */
async function gracefulShutdown(signal: string): Promise<void> {
  if (isShuttingDown) {
    logger.warn('Shutdown already in progress, ignoring signal', { signal });
    return;
  }
  isShuttingDown = true;
  logger.info(`Received ${signal}, starting graceful shutdown...`, { signal });
  // SIGTERM/SIGINT are expected shutdowns; crashes should exit non-zero.
  const exitCode = signal === 'SIGTERM' || signal === 'SIGINT' ? 0 : 1;
  // Set a hard timeout for forced shutdown
  // Safely parse with validation: NaN, negative, or zero values fall back to default
  const parsedTimeout = Number(process.env.SHUTDOWN_TIMEOUT_MS);
  const SHUTDOWN_TIMEOUT_MS =
    Number.isFinite(parsedTimeout) && parsedTimeout > 0
      ? parsedTimeout
      : 30_000;
  const parsedOtelShutdownTimeout = Number(
    process.env.OTEL_SHUTDOWN_TIMEOUT_MS
  );
  const OTEL_SHUTDOWN_TIMEOUT_MS =
    Number.isFinite(parsedOtelShutdownTimeout) && parsedOtelShutdownTimeout > 0
      ? Math.min(parsedOtelShutdownTimeout, SHUTDOWN_TIMEOUT_MS)
      : Math.min(5_000, SHUTDOWN_TIMEOUT_MS);
  const shutdownOpenTelemetryWithTimeout = async (): Promise<void> => {
    const timeoutError = new Error(
      `OpenTelemetry shutdown timed out after ${OTEL_SHUTDOWN_TIMEOUT_MS}ms`
    );
    const timeoutPromise = new Promise<never>((_, reject) => {
      const timer = setTimeout(
        () => reject(timeoutError),
        OTEL_SHUTDOWN_TIMEOUT_MS
      );
      timer.unref();
    });
    try {
      await Promise.race([shutdownOpenTelemetrySdk(), timeoutPromise]);
    } catch (error) {
      logger.warn('OpenTelemetry shutdown did not complete cleanly', {
        timeoutMs: OTEL_SHUTDOWN_TIMEOUT_MS,
        error: error instanceof Error ? error.message : error,
      });
    }
  };
  const forceShutdownTimer = setTimeout(() => {
    logger.error('Graceful shutdown timed out, forcing exit', {
      timeoutMs: SHUTDOWN_TIMEOUT_MS,
    });
    // Forcefully destroy any remaining sockets to avoid hanging the process.
    for (const socket of activeConnections) {
      socket.destroy();
    }
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);
  // Don't let the timeout keep the process alive if we finish early
  forceShutdownTimer.unref();
  try {
    // Step 1: Stop cron jobs ASAP to prevent new work during drain
    // This ensures no new background tasks start while we're shutting down
    await withOtelSpan('server.shutdown.stop_crons', { signal }, async () => {
      logger.info('Stopping cron jobs...');
      stopReconciliationCron();
      stopWebhookEventsCleanupCron();
      logger.info('Cron jobs stopped');
    });
    // Step 2: Proactively close keep-alive connections so server.close() can finish
    for (const socket of activeConnections) {
      socket.end();
    }
    // Step 3: Stop accepting new connections and drain existing ones
    await withOtelSpan(
      'server.shutdown.close_http_server',
      { signal, active_connection_count: activeConnections.size },
      async () => {
        logger.info('Closing HTTP server (stop accepting new connections)...');
        await new Promise<void>((resolve, reject) => {
          server.close((err) => {
            if (err) {
              logger.error('Error closing HTTP server', {
                error: err.message,
              });
              reject(err);
            } else {
              logger.info('HTTP server closed successfully');
              resolve();
            }
          });
        });
      }
    );
    await withOtelSpan(
      'server.shutdown.close_resources',
      { signal },
      async () => {
        // Step 4: Close database connections
        logger.info('Closing database connections...');
        const closeOperations: Promise<void>[] = [];
        // Close Neo4j connection if initialized
        const neo4jClient = getNeo4jClient();
        if (neo4jClient.isInitialized()) {
          closeOperations.push(
            neo4jClient
              .close()
              .then(() => {
                logger.info('Neo4j connection closed');
              })
              .catch((err: unknown) => {
                logger.error('Error closing Neo4j connection', {
                  error: err instanceof Error ? err.message : err,
                });
              })
          );
        }
        if (langfuse) {
          closeOperations.push(
            langfuse
              .flushAsync()
              .then(() => {
                logger.info('Langfuse flushed');
              })
              .catch((err: unknown) => {
                logger.warn('Langfuse flush failed', {
                  error: err instanceof Error ? err.message : err,
                });
              })
          );
        }
        // Wait for all close operations (with individual error handling)
        await Promise.allSettled(closeOperations);
      }
    );
    // OTel shutdown must not be wrapped in a span: span.end() fires after
    // shutdownOpenTelemetrySdk() closes the exporter, so the span is silently
    // dropped. Call directly instead.
    await shutdownOpenTelemetryWithTimeout();
    logger.info('All connections closed, shutdown complete');
    clearTimeout(forceShutdownTimer);
    process.exit(exitCode);
  } catch (error) {
    logger.error('Error during graceful shutdown', {
      error: error instanceof Error ? error.message : error,
    });
    clearTimeout(forceShutdownTimer);
    await shutdownOpenTelemetryWithTimeout();
    process.exit(1);
  }
}
// Register signal handlers for graceful shutdown
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
// Handle uncaught exceptions - log and exit
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception, shutting down', {
    error: error.message,
    stack: error.stack,
  });
  gracefulShutdown('uncaughtException');
});
// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled promise rejection', {
    reason: reason instanceof Error ? reason.message : reason,
    promise: String(promise),
  });
  // Don't exit on unhandled rejections, but log them
  // This matches Node.js default behavior in newer versions
});
/**
 * Recover repos that were left in 'indexing' or 'queued' state from a
 * previous server crash.  Resets them to 'queued' so the next manual
 * trigger or cron run can pick them up cleanly.
 */
async function recoverStaleIndexingStatuses(): Promise<void> {
  return withOtelSpan(
    'server.startup.recover_stale_indexing',
    { 'server.port': Number(process.env.PORT ?? 8080) },
    async (span) => {
      try {
        const allRepos = await repoMetadataRepository.getAllIndexedRepos();
        let recovered = 0;
        span?.setAttribute?.('indexing.candidate_repo_count', allRepos.length);
        for (const repo of allRepos) {
          const meta = await repoMetadataRepository.get(
            repo.installationId,
            repo.repoName
          );
          if (!meta) continue;
          if (
            meta.indexingStatus === 'indexing' ||
            meta.indexingStatus === 'queued'
          ) {
            await repoMetadataRepository.updateStatus(
              repo.installationId,
              repo.repoName,
              'queued',
              'Reset on startup — previous run did not complete'
            );
            recovered++;
            logger.warn('[STARTUP] Reset stale indexing status to queued', {
              installationId: repo.installationId,
              repoName: repo.repoName,
              previousStatus: meta.indexingStatus,
            });
          }
        }
        span?.setAttribute?.('indexing.recovered_repo_count', recovered);
        if (recovered > 0) {
          logger.info(
            `[STARTUP] Recovered ${recovered} repo(s) with stale indexing status`
          );
        }
      } catch (error) {
        logger.error('[STARTUP] Failed to recover stale indexing statuses', {
          error: error instanceof Error ? error.message : error,
        });
      }
    }
  );
}
server.listen(PORT, () => {
  // Get the actual bound port (important when PORT=0 is used for OS-assigned port)
  const address = server.address();
  const actualPort =
    address && typeof address === 'object' ? address.port : PORT;
  logger.info(`Server running on port ${actualPort}`);
  void withOtelSpan(
    'server.startup.bootstrap',
    { 'server.port': Number(actualPort) },
    async () => {
      // Recover repos stuck in 'indexing'/'queued' from a previous crash
      await recoverStaleIndexingStatuses().catch((err) => {
        logger.error('[STARTUP] recoverStaleIndexingStatuses threw', {
          error: err instanceof Error ? err.message : err,
        });
      });
      // Initialize reconciliation cron if enabled
      if (process.env.ENABLE_RECONCILIATION_CRON !== 'false') {
        await withOtelSpan(
          'server.startup.start_reconciliation_cron',
          { 'server.port': Number(actualPort) },
          async () => {
            try {
              // Cron builds per-installation config inside the job loops
              startReconciliationCron();
            } catch (cronError) {
              logger.error('Failed to start reconciliation cron', {
                error:
                  cronError instanceof Error ? cronError.message : cronError,
              });
            }
          }
        );
      }
      // Initialize webhook_events cleanup cron if enabled
      if (process.env.ENABLE_WEBHOOK_EVENTS_CLEANUP_CRON !== 'false') {
        await withOtelSpan(
          'server.startup.start_webhook_cleanup_cron',
          { 'server.port': Number(actualPort) },
          async () => {
            try {
              startWebhookEventsCleanupCron();
            } catch (cronError) {
              logger.error('Failed to start webhook_events cleanup cron', {
                error:
                  cronError instanceof Error ? cronError.message : cronError,
              });
            }
          }
        );
      }
    }
  ).catch((err) => {
    logger.error('[STARTUP] startup bootstrap span failed', {
      error: err instanceof Error ? err.message : err,
    });
  });
});
