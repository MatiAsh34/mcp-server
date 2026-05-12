import dotenv from "dotenv";
dotenv.config();

import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createRemoteJWKSet, jwtVerify } from "jose";

import { executeQueryTool } from "./tools/executeQuery.js";

// --- AuthKit Config ---
const AUTHKIT_DOMAIN = process.env.WORKOS_AUTHKIT_DOMAIN; // e.g. "your-app.authkit.app"
const AUTHKIT_CLIENT_ID = process.env.AUTHKIT_CLIENT_ID;
const MCP_SERVER_URL = process.env.MCP_SERVER_URL; // e.g. "https://your-render-app.onrender.com"

const JWKS = createRemoteJWKSet(
  new URL(`https://${AUTHKIT_DOMAIN}/oauth2/jwks`)
);

const WWW_AUTHENTICATE_HEADER =
  `Bearer resource_metadata="${MCP_SERVER_URL}/.well-known/oauth-protected-resource"`;

// --- Express App ---
const app = express();
app.use(express.json());

// --- Metadata Endpoints ---

// Protected Resource Metadata (RFC 9728)
// Le indica a los clientes MCP qué authorization server usar
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [`https://${AUTHKIT_DOMAIN}`],
    bearer_methods_supported: ["header"],
  });
});

// Proxy de metadata OAuth Authorization Server de AuthKit
// Algunos clientes MCP buscan este endpoint directamente en tu dominio
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  res.json({
    issuer: `https://${AUTHKIT_DOMAIN}`,
    authorization_endpoint: `https://${AUTHKIT_DOMAIN}/oauth2/authorize`,
    token_endpoint: `https://${AUTHKIT_DOMAIN}/oauth2/token`,
    jwks_uri: `https://${AUTHKIT_DOMAIN}/oauth2/jwks`,
    response_types_supported: ["code"],
    grant_types_supported: [
      "authorization_code",
      "refresh_token"
    ],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["openid", "profile", "email"],
  });
});

// --- Middleware Bearer Token ---
async function bearerTokenMiddleware(req, res, next) {
  const token = req.headers.authorization?.match(/^Bearer (.+)$/)?.[1];

  if (!token) {
    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "No token provided." });
  }

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://${AUTHKIT_DOMAIN}`,
    });

    // Adjunta información del usuario al request
    req.userId = payload.sub;
    next();
  } catch (err) {
    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "Invalid bearer token." });
  }
}

// --- Factory MCP Server ---
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

// --- Endpoint MCP protegido ---
app.post("/mcp", bearerTokenMiddleware, async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined, // stateless
  });

  const server = createMcpServer();

  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

// --- Iniciar servidor ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`MCP server running on http://localhost:${PORT}/mcp`);
});