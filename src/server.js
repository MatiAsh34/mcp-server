import dotenv from "dotenv";
dotenv.config();

import express from "express";
import { jwtVerify, createRemoteJWKSet } from "jose";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { executeQueryTool } from "./tools/executeQuery.js";

const AUTHKIT_DOMAIN = process.env.WORKOS_AUTHKIT_DOMAIN;
const MCP_SERVER_URL  = process.env.MCP_SERVER_URL;

// BASE_URL: solo protocolo + host, sin path.
// Si MCP_SERVER_URL = "https://tudominio.com/mcp", BASE_URL = "https://tudominio.com"
// Podés sobreescribirla con BASE_URL en el .env si necesitás otro valor.
const BASE_URL = process.env.BASE_URL ?? (() => {
  const u = new URL(MCP_SERVER_URL);
  return `${u.protocol}//${u.host}`;
})();

const JWKS = createRemoteJWKSet(new URL(`${AUTHKIT_DOMAIN}/oauth2/jwks`));

const WWW_AUTHENTICATE_HEADER = [
  'Bearer error="unauthorized"',
  'error_description="Se requiere autorización"',
  `resource_metadata="${MCP_SERVER_URL}/.well-known/oauth-protected-resource"`,
].join(", ");

// ─── Middleware ───────────────────────────────────────────────────────────────

const bearerTokenMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.match(/^Bearer (.+)$/)?.[1];

  if (!token) {
    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "No se proporcionó token de autorización." });
  }

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: AUTHKIT_DOMAIN,
      audience: MCP_SERVER_URL,
    });

    req.authPayload = payload;
    next();
  } catch (err) {
    console.error("Token inválido:", err.message);
    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "Token Bearer inválido o expirado." });
  }
};

// ─── App ──────────────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── OAuth Discovery Endpoints ────────────────────────────────────────────────

/**
 * Protected Resource Metadata (RFC 9728)
 * Le dice al cliente MCP que este server ES el authorization server.
 */
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [BASE_URL],
    bearer_methods_supported: ["header"],
  });
});

/**
 * Authorization Server Metadata (RFC 8414)
 *
 * Claude Web busca este endpoint en el mismo origen que el MCP server.
 * Lo construimos directamente sin depender de un fetch a WorkOS,
 * apuntando authorize/token a nuestros propios proxies.
 *
 * registration_endpoint sigue apuntando a WorkOS para que DCR/CIMD funcione.
 */
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  res.json({
    issuer: BASE_URL,
    authorization_endpoint:               `${BASE_URL}/api/oauth/authorize`,
    token_endpoint:                        `${BASE_URL}/api/oauth/token`,
    registration_endpoint:                 `${AUTHKIT_DOMAIN}/oauth2/register`,
    scopes_supported:                      ["openid", "profile", "email", "offline_access"],
    response_types_supported:              ["code"],
    response_modes_supported:              ["query"],
    grant_types_supported:                 ["authorization_code", "refresh_token"],
    code_challenge_methods_supported:      ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
  });
});

// ─── OAuth Proxy Endpoints ────────────────────────────────────────────────────

/**
 * Proxy Authorize → WorkOS
 * Claude redirige al usuario acá; nosotros hacemos 302 a WorkOS con los mismos params.
 */
app.get("/api/oauth/authorize", (req, res) => {
  const upstream = new URL(`${AUTHKIT_DOMAIN}/oauth2/authorize`);

  for (const [key, value] of Object.entries(req.query)) {
    upstream.searchParams.set(key, value);
  }

  console.log(`[OAuth] Authorize → ${upstream.toString()}`);
  res.redirect(302, upstream.toString());
});

/**
 * Proxy Token → WorkOS
 * Claude hace POST acá para intercambiar el code por un access token.
 */
app.post("/api/oauth/token", async (req, res) => {
  try {
    const upstreamUrl = `${AUTHKIT_DOMAIN}/oauth2/token`;
    const body = new URLSearchParams(req.body).toString();

    console.log(`[OAuth] Token exchange → ${upstreamUrl}`);

    const upstream = await fetch(upstreamUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...(req.headers.authorization
          ? { Authorization: req.headers.authorization }
          : {}),
      },
      body,
    });

    const data = await upstream.json();
    res.status(upstream.status).json(data);
  } catch (err) {
    console.error("Error en token proxy:", err.message);
    res.status(502).json({ error: "Error al contactar el authorization server." });
  }
});

// ─── MCP Endpoint ─────────────────────────────────────────────────────────────

function createMcpServer() {
  const server = new Server(
    { name: "postgres-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: executeQueryTool.name,
        description: "Ejecuta consultas SQL SELECT en PostgreSQL",
        inputSchema: {
          type: "object",
          properties: { query: { type: "string" } },
          required: ["query"],
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name === executeQueryTool.name) {
      return await executeQueryTool.handler(request.params.arguments);
    }
    throw new Error("Tool no encontrada");
  });

  return server;
}

app.post("/mcp", bearerTokenMiddleware, async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  const server = createMcpServer();
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

// ─── Start ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`MCP server corriendo en http://localhost:${PORT}/mcp`);
  console.log(`BASE_URL: ${BASE_URL}`);
  console.log(`MCP_SERVER_URL: ${MCP_SERVER_URL}`);
});