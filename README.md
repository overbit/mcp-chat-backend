# MCP Chat Backend

Node.js backend server that integrates GitHub Copilot SDK with the MCP OpenAPI Gateway.

## Architecture

```
React App → Backend (Copilot SDK) → MCP Gateway → APIs (User/Order/Fund)
```

## Features

- **Copilot SDK Integration**: Uses GitHub Copilot's agentic runtime for natural language interactions
- **MCP Connection**: Connects to MCP OpenAPI Gateway for tool execution
- **Dual Mode Support**: 
  - PlatformOPS mode (unauthenticated)
  - Investor/AssetManager mode (authenticated with Auth0 token forwarding)
- **Streaming Responses**: Server-Sent Events (SSE) for real-time streaming
- **Session Management**: In-memory sessions with TTL and ownership checks

## Prerequisites

1. **GitHub Copilot CLI** installed and authenticated
   ```bash
   copilot --version
   ```

2. **MCP Gateway** running (both modes):
   - PlatformOPS: `http://localhost:8001/mcp`
   - Authenticated: `http://localhost:8000/mcp`

## Setup

```bash
npm install
cp .env.example .env
```

Configure environment variables:

```bash
PORT=4000
LOG_LEVEL=info
NODE_ENV=development
CORS_ORIGINS=http://localhost:5173
MCP_URL_PLATFORMOPS=http://localhost:8001/mcp
MCP_URL_AUTHENTICATED=http://localhost:8000/mcp
SESSION_TTL_SECONDS=3600
SESSION_CLEANUP_INTERVAL_SECONDS=60
LIST_SESSIONS_ENABLED=true
```

## Development

```bash
npm run dev
```

## Production Build

```bash
npm run build
npm start
```

## API Endpoints

### Health Check
```
GET /health
```

### Create Session
```
POST /api/sessions
Headers: Authorization: Bearer <token>   // required in investor mode
Body: {
  mode: "platformops" | "investor",
  model: "gpt-4.1",
  sessionId?: string
}
```

### Send Message (Streaming)
```
POST /api/sessions/:sessionId/messages
Headers: Authorization: Bearer <token>   // required for investor sessions
Body: { prompt: string }
Response: text/event-stream
```

Events:
- `status` - Backend runtime stage updates (dispatch, intent, tool lifecycle, idle)
- `message_delta` - Incremental content chunk
- `tool_start` - Tool execution started
- `tool_progress` - Tool progress update
- `tool_partial_result` - Tool partial output
- `tool_complete` - Tool execution finished
- `message_end` - Message generation complete
- `error` - Error occurred

### Get Session
```
GET /api/sessions/:sessionId
```

### List Sessions
```
GET /api/sessions
```
Disabled by default in production unless `LIST_SESSIONS_ENABLED=true`.

### Delete Session
```
DELETE /api/sessions/:sessionId
```

## Available Models

The backend supports all Copilot SDK models:
- `gpt-4.1`
- `gpt-4o`
- `claude-sonnet-4.5`
- `claude-opus-4.5`
- And more...

## Session Flow

1. Client creates session with mode (platformops/investor) and model
2. Backend creates Copilot session with MCP connection
3. Client sends messages to session
4. Copilot processes message, calls MCP tools as needed
5. Backend streams events back to client (SSE)
6. Tool calls are handled automatically by Copilot SDK

## Tool Calling

Tools are automatically discovered from the MCP Gateway. Copilot SDK:
1. Receives tool definitions from MCP server
2. Decides when to call tools based on user input
3. Executes tool calls via MCP HTTP protocol
4. Incorporates tool results into response

No manual tool orchestration needed!

## Session Storage & Cleanup

Sessions are stored in-memory with:
- Per-session ownership checks (investor sessions are token-bound)
- TTL expiration (`SESSION_TTL_SECONDS`)
- Periodic cleanup (`SESSION_CLEANUP_INTERVAL_SECONDS`)

Note: in-memory sessions do not survive server restarts.

## Error Handling

The server handles:
- Copilot CLI not installed
- MCP Gateway unreachable
- Session not found
- Tool execution errors
- Streaming connection drops

## Integration with React App

The React app connects to this backend instead of directly calling Gemini/Ollama:

```typescript
// Create session
const response = await fetch('http://localhost:4000/api/sessions', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${accessToken}`, // investor mode only
  },
  body: JSON.stringify({
    mode: isAuthenticated ? 'investor' : 'platformops',
    model: selectedModel,
  }),
});

// Send message (streaming SSE over fetch)
const streamResponse = await fetch(`http://localhost:4000/api/sessions/${sessionId}/messages`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${accessToken}`, // investor mode only
  },
  body: JSON.stringify({ prompt: userInput }),
});
```

## Logging

The server logs:
- Session creation/deletion
- Message handling
- Tool execution
- Errors

Set `LOG_LEVEL=debug` for verbose Copilot SDK logs.

## Security Considerations

1. **CORS**: Configure `CORS_ORIGINS` to match your frontend URLs
2. **Auth Tokens**: Pass access tokens via `Authorization` header, never request body
3. **Session Isolation**: Investor sessions are bound to the token owner
4. **Input Validation**: All inputs are validated before processing

## Deployment

### Docker

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY dist ./dist
CMD ["node", "dist/index.js"]
```

### Environment Variables

Required in production:
- `PORT`
- `CORS_ORIGINS`
- `MCP_URL_PLATFORMOPS`
- `MCP_URL_AUTHENTICATED`

## Troubleshooting

**Copilot CLI not found:**
```bash
which copilot
# Install: https://docs.github.com/en/copilot/copilot-cli
```

**MCP Gateway connection error:**
- Verify MCP Gateway is running
- Check firewall/network rules
- Verify MCP URLs in .env

**Session not persisting:**
- Sessions are stored in memory by default
- For production, implement Redis session store

## Performance

- Single Copilot client shared across all sessions
- Streaming reduces time-to-first-token
- Connection pooling to MCP Gateway
- Automatic cleanup of idle sessions

## Future Enhancements

- [ ] Redis session store for multi-instance deployments
- [ ] Rate limiting per user/session
- [ ] Metrics and monitoring
- [ ] WebSocket support (in addition to SSE)
- [ ] Custom tool definitions alongside MCP tools
- [ ] Message history export
