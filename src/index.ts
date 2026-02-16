import crypto from 'node:crypto'
import cors from 'cors'
import dotenv from 'dotenv'
import express, { type Request, type Response } from 'express'
import { CopilotClient, type CopilotSession, type SessionEvent } from '@github/copilot-sdk'
import { z } from 'zod'

dotenv.config()

type ChatMode = 'platformops' | 'investor'
type LogLevel = 'info' | 'none' | 'error' | 'warning' | 'debug' | 'all'

interface SessionRecord {
  session: CopilotSession
  ownerKey: string
  mode: ChatMode
  model: string
  createdAt: string
  lastAccessAt: number
}

const app = express()
const PORT = Number(process.env.PORT ?? 4000)
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS ?? 3600)
const SESSION_CLEANUP_INTERVAL_SECONDS = Number(process.env.SESSION_CLEANUP_INTERVAL_SECONDS ?? 60)
const isProduction = process.env.NODE_ENV === 'production'
const listSessionsEnabled =
  process.env.LIST_SESSIONS_ENABLED != null
    ? process.env.LIST_SESSIONS_ENABLED === 'true'
    : !isProduction

const allowedOrigins =
  process.env.CORS_ORIGINS?.split(',').map(origin => origin.trim()).filter(Boolean) ?? [
    'http://localhost:5173'
  ]

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization']
  })
)
app.use(express.json({ limit: '1mb' }))

let copilotClient: CopilotClient | null = null
const sessions = new Map<string, SessionRecord>()

const createSessionBodySchema = z.object({
  mode: z.enum(['platformops', 'investor']).default('platformops'),
  model: z.string().trim().min(1).max(120).default('gpt-4.1'),
  sessionId: z.string().trim().min(1).max(200).optional()
})

const messageBodySchema = z.object({
  prompt: z.string().trim().min(1).max(20000)
})

function getBearerToken(req: Request): string | undefined {
  const authorization = req.header('authorization')
  if (!authorization) return undefined
  const match = authorization.match(/^Bearer\s+(.+)$/i)
  return match?.[1]?.trim()
}

function ownerKeyFromToken(token: string): string {
  const tokenParts = token.split('.')
  if (tokenParts.length >= 2) {
    try {
      const payload = JSON.parse(
        Buffer.from(tokenParts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')
      ) as { sub?: unknown }
      if (typeof payload.sub === 'string' && payload.sub.trim()) {
        return `investor:${payload.sub.trim()}`
      }
    } catch {
      // fallback to hash below
    }
  }

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex').slice(0, 16)
  return `investor:${tokenHash}`
}

function getOwnerKey(mode: ChatMode, token?: string): string {
  if (mode === 'investor') {
    if (!token) {
      throw new Error('Authentication is required for investor mode.')
    }
    return ownerKeyFromToken(token)
  }
  return 'platformops'
}

function canAccessSession(
  req: Request,
  record: SessionRecord
): { ok: true } | { ok: false; status: number; error: string } {
  if (record.mode !== 'investor') {
    return { ok: true }
  }

  const bearerToken = getBearerToken(req)
  if (!bearerToken) {
    return {
      ok: false,
      status: 401,
      error: 'Authorization header is required for investor sessions.'
    }
  }
  if (ownerKeyFromToken(bearerToken) !== record.ownerKey) {
    return { ok: false, status: 403, error: 'You do not have access to this session.' }
  }
  return { ok: true }
}

function touchSession(record: SessionRecord): void {
  record.lastAccessAt = Date.now()
}

function cleanupExpiredSessions(): void {
  const now = Date.now()
  let removed = 0
  for (const [sessionId, record] of sessions.entries()) {
    if (now - record.lastAccessAt > SESSION_TTL_SECONDS * 1000) {
      sessions.delete(sessionId)
      removed += 1
    }
  }
  if (removed > 0) {
    console.log(`[Session] Cleaned up ${removed} expired session(s).`)
  }
}

function parseValidationError(error: z.ZodError): string {
  return error.issues.map(issue => `${issue.path.join('.') || 'body'}: ${issue.message}`).join('; ')
}

function toCompactSnippet(value: unknown, maxLength = 220): string | undefined {
  if (value == null) return undefined
  const asString =
    typeof value === 'string'
      ? value
      : (() => {
          try {
            return JSON.stringify(value)
          } catch {
            return String(value)
          }
        })()
  const normalized = asString.replace(/\s+/g, ' ').trim()
  if (!normalized) return undefined
  return normalized.length > maxLength ? `${normalized.slice(0, maxLength - 1)}…` : normalized
}

async function initCopilot(): Promise<void> {
  try {
    const logLevel = (process.env.LOG_LEVEL ?? 'info') as LogLevel
    copilotClient = new CopilotClient({ logLevel })
    await copilotClient.start()
    console.log('[Copilot] Client initialized')
  } catch (error) {
    console.error('[Copilot] Failed to initialize client:', error)
    throw error
  }
}

const cleanupTimer = setInterval(cleanupExpiredSessions, SESSION_CLEANUP_INTERVAL_SECONDS * 1000)
cleanupTimer.unref()

async function shutdown(signal: string): Promise<void> {
  console.log(`\n[Server] Received ${signal}, shutting down...`)
  clearInterval(cleanupTimer)
  if (copilotClient) {
    await copilotClient.stop()
  }
  process.exit(0)
}

process.on('SIGINT', () => {
  void shutdown('SIGINT')
})
process.on('SIGTERM', () => {
  void shutdown('SIGTERM')
})

app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    copilot: Boolean(copilotClient),
    sessions: sessions.size
  })
})

app.post('/api/sessions', async (req: Request, res: Response) => {
  try {
    if (!copilotClient) {
      return res.status(503).json({ error: 'Copilot client not initialized.' })
    }

    const parsedBody = createSessionBodySchema.safeParse(req.body)
    if (!parsedBody.success) {
      return res.status(400).json({ error: parseValidationError(parsedBody.error) })
    }

    const { mode, model, sessionId } = parsedBody.data
    const bearerToken = getBearerToken(req)

    if (mode === 'investor' && !bearerToken) {
      return res.status(401).json({ error: 'Authorization header is required for investor mode.' })
    }

    const mcpUrl =
      mode === 'investor'
        ? process.env.MCP_URL_AUTHENTICATED || 'http://localhost:8000/mcp'
        : process.env.MCP_URL_PLATFORMOPS || 'http://localhost:8001/mcp'

    const ownerKey = getOwnerKey(mode, bearerToken)

    const session = await copilotClient.createSession({
      sessionId,
      model,
      streaming: true,
      mcpServers: {
        gainsway: {
          type: 'http',
          url: mcpUrl,
          tools: ['*'],
          headers:
            mode === 'investor' && bearerToken
              ? { authorization: `Bearer ${bearerToken}` }
              : undefined
        }
      },
      systemMessage: {
        content:
          mode === 'investor'
            ? 'You are an AI assistant for Gainsway investors and asset managers. Help users manage their accounts, orders, and funds.'
            : 'You are an AI assistant for Gainsway platform operations. Help users with platform management tasks.'
      }
    })

    const now = Date.now()
    sessions.set(session.sessionId, {
      session,
      ownerKey,
      mode,
      model,
      createdAt: new Date(now).toISOString(),
      lastAccessAt: now
    })

    return res.json({
      sessionId: session.sessionId,
      mode,
      model
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    console.error('[Session] Failed to create session:', error)
    return res.status(500).json({ error: 'Failed to create session.', details: message })
  }
})

app.post('/api/sessions/:sessionId/messages', async (req: Request, res: Response) => {
  if (!copilotClient) {
    return res.status(503).json({ error: 'Copilot client not initialized.' })
  }

  const sessionId = req.params.sessionId as string
  const record = sessions.get(sessionId)
  if (!record) {
    return res.status(404).json({ error: 'Session not found.' })
  }

  const access = canAccessSession(req, record)
  if (!access.ok) {
    return res.status(access.status).json({ error: access.error })
  }

  const parsedBody = messageBodySchema.safeParse(req.body)
  if (!parsedBody.success) {
    return res.status(400).json({ error: parseValidationError(parsedBody.error) })
  }

  touchSession(record)
  const { prompt } = parsedBody.data

  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache')
  res.setHeader('Connection', 'keep-alive')
  res.flushHeaders?.()

  const requestStartedAt = Date.now()
  let fullContent = ''
  let closed = false
  let assistantOutputStarted = false
  const toolNameByCallId = new Map<string, string>()

  const emit = (eventName: string, payload: Record<string, unknown>) => {
    if (closed || res.writableEnded) return
    res.write(`event: ${eventName}\n`)
    res.write(
      `data: ${JSON.stringify({
        ...payload,
        timestamp: new Date().toISOString()
      })}\n\n`
    )
  }

  const emitStatus = (stage: string, message: string, data: Record<string, unknown> = {}) => {
    emit('status', { stage, message, ...data })
  }

  emitStatus('request_received', 'Backend accepted request.', {
    sessionId,
    mode: record.mode,
    model: record.model,
    promptChars: prompt.length
  })

  const keepAliveTimer = setInterval(() => {
    if (!res.writableEnded) {
      res.write(': keepalive\n\n')
    }
  }, 15000)

  let unsubscribe: (() => void) | null = null
  const cleanup = () => {
    clearInterval(keepAliveTimer)
    unsubscribe?.()
    unsubscribe = null
  }

  const closeStream = () => {
    if (closed) return
    closed = true
    cleanup()
    if (!res.writableEnded) {
      res.end()
    }
  }

  const eventHandler = (event: SessionEvent) => {
    if (closed || res.writableEnded) {
      return
    }

    switch (event.type) {
      case 'assistant.intent': {
        emitStatus('intent_detected', `Intent: ${event.data.intent}`, {
          intent: event.data.intent
        })
        break
      }
      case 'assistant.message': {
        if (typeof event.data.content === 'string' && event.data.content.length > 0) {
          fullContent = event.data.content
        }
        break
      }
      case 'assistant.message_delta': {
        if (!assistantOutputStarted) {
          assistantOutputStarted = true
          emitStatus('assistant_streaming', 'Assistant started generating response.')
        }
        const delta = event.data.deltaContent ?? ''
        fullContent += delta
        emit('message_delta', { delta, full: fullContent })
        break
      }
      case 'tool.execution_start': {
        const toolName = event.data.mcpToolName ?? event.data.toolName
        toolNameByCallId.set(event.data.toolCallId, toolName)
        emit('tool_start', {
          toolCallId: event.data.toolCallId,
          toolName: event.data.toolName,
          mcpServerName: event.data.mcpServerName,
          mcpToolName: event.data.mcpToolName,
          argumentsSummary: toCompactSnippet(event.data.arguments)
        })
        emitStatus('tool_start', `Running tool ${toolName}`, {
          toolCallId: event.data.toolCallId,
          toolName
        })
        break
      }
      case 'tool.execution_progress': {
        emit('tool_progress', {
          toolCallId: event.data.toolCallId,
          progressMessage: event.data.progressMessage
        })
        emitStatus('tool_progress', event.data.progressMessage, {
          toolCallId: event.data.toolCallId,
          toolName: toolNameByCallId.get(event.data.toolCallId)
        })
        break
      }
      case 'tool.execution_partial_result': {
        emit('tool_partial_result', {
          toolCallId: event.data.toolCallId,
          partialOutput: toCompactSnippet(event.data.partialOutput)
        })
        break
      }
      case 'tool.execution_complete': {
        const toolName = toolNameByCallId.get(event.data.toolCallId)
        emit('tool_complete', {
          toolCallId: event.data.toolCallId,
          toolName,
          success: event.data.success,
          result: event.data.result,
          error: event.data.error
        })
        emitStatus(
          'tool_complete',
          event.data.success
            ? `Tool ${toolName ?? event.data.toolCallId} completed successfully.`
            : `Tool ${toolName ?? event.data.toolCallId} failed.`,
          {
            toolCallId: event.data.toolCallId,
            toolName,
            success: event.data.success,
            error: event.data.error?.message
          }
        )
        break
      }
      case 'session.idle': {
        emitStatus('session_idle', 'Copilot finished processing.', {
          durationMs: Date.now() - requestStartedAt,
          responseChars: fullContent.length
        })
        emit('message_end', { content: fullContent })
        closeStream()
        break
      }
      case 'session.error': {
        emitStatus('session_error', `Copilot session error: ${event.data.message}`)
        emit('error', { error: event.data.message })
        closeStream()
        break
      }
      default:
        break
    }
  }

  unsubscribe = record.session.on(eventHandler)
  res.on('close', closeStream)

  try {
    emitStatus('dispatching', 'Prompt sent to Copilot runtime.')
    await record.session.send({ prompt })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    emitStatus('dispatch_error', `Failed to dispatch prompt: ${message}`)
    emit('error', { error: message })
    closeStream()
  }

  return undefined
})

app.get('/api/sessions/:sessionId', (req: Request, res: Response) => {
  const sessionId = req.params.sessionId as string
  const record = sessions.get(sessionId)
  if (!record) {
    return res.status(404).json({ error: 'Session not found.' })
  }

  const access = canAccessSession(req, record)
  if (!access.ok) {
    return res.status(access.status).json({ error: access.error })
  }

  touchSession(record)
  return res.json({
    sessionId,
    mode: record.mode,
    model: record.model,
    createdAt: record.createdAt
  })
})

app.delete('/api/sessions/:sessionId', async (req: Request, res: Response) => {
  const sessionId = req.params.sessionId as string
  const record = sessions.get(sessionId)
  if (!record) {
    return res.status(404).json({ error: 'Session not found.' })
  }

  const access = canAccessSession(req, record)
  if (!access.ok) {
    return res.status(access.status).json({ error: access.error })
  }

  sessions.delete(sessionId)

  if (copilotClient) {
    try {
      await copilotClient.deleteSession(sessionId)
    } catch (error) {
      console.warn(`[Session] Failed to delete session ${sessionId} from Copilot SDK:`, error)
    }
  }

  return res.json({ success: true })
})

app.get('/api/sessions', (req: Request, res: Response) => {
  if (!listSessionsEnabled) {
    return res.status(404).json({ error: 'Not found.' })
  }

  const requesterToken = getBearerToken(req)
  const requesterOwnerKey = requesterToken ? ownerKeyFromToken(requesterToken) : null

  const sessionList = Array.from(sessions.entries())
    .filter(([, record]) => {
      if (record.mode !== 'investor') return true
      return requesterOwnerKey === record.ownerKey
    })
    .map(([sessionId, record]) => ({
      sessionId,
      mode: record.mode,
      model: record.model,
      createdAt: record.createdAt
    }))

  return res.json({ sessions: sessionList })
})

async function start(): Promise<void> {
  try {
    await initCopilot()
    app.listen(PORT, () => {
      console.log(`[Server] Running on http://localhost:${PORT}`)
      console.log(`[Server] Health check: http://localhost:${PORT}/health`)
    })
  } catch (error) {
    console.error('[Server] Failed to start:', error)
    process.exit(1)
  }
}

void start()
