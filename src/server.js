import dotenv from "dotenv";
dotenv.config();

import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { executeQueryTool } from "./tools/executeQuery.js";
import { setupAuthRoutes } from "./auth.js";
import { authMiddleware } from "./middleware.js";

const app = express();
app.use(express.json());

setupAuthRoutes(app);

function createMcpServer() {
  const server = new Server(
    { name: "postgres-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: executeQueryTool.name,
          description: "Ejecuta consultas SQL SELECT en PostgreSQL",
          inputSchema: {
            type: "object",
            properties: {
              query: { type: "string" },
            },
            required: ["query"],
          },
        },
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name === executeQueryTool.name) {
      return await executeQueryTool.handler(request.params.arguments);
    }
    throw new Error("Tool no encontrada");
  });

  return server;
}

// OAuth metadata - le dice a mcp-remote dónde está el auth server
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.json({
    resource: "https://mcp-server-rga9.onrender.com",
    authorization_servers: ["https://seamless-ice-72-staging.authkit.app"],
    bearer_methods_supported: ["header"],
  });
});

// Dynamic client registration - requerido por mcp-remote
app.post("/register", (req, res) => {
  res.json({
    client_id: process.env.WORKOS_CLIENT_ID,
    client_secret: process.env.WORKOS_API_KEY,
    redirect_uris: [process.env.WORKOS_REDIRECT_URI],
  });
});

app.post("/mcp", authMiddleware, async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  const server = createMcpServer();

  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`MCP server corriendo en http://localhost:${PORT}/mcp`);
});
