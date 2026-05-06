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

// ─── Config ────────────────────────────────────────────────────────────────────
// WORKOS_AUTHKIT_DOMAIN  → e.g. "https://your-subdomain.authkit.app"
// MCP_SERVER_URL         → e.g. "https://mcp.example.com"  (public URL de este server)
const AUTHKIT_DOMAIN = process.env.WORKOS_AUTHKIT_DOMAIN;
const MCP_SERVER_URL = process.env.MCP_SERVER_URL;

if (!AUTHKIT_DOMAIN || !MCP_SERVER_URL) {
  throw new Error(
    "Faltan variables de entorno: WORKOS_AUTHKIT_DOMAIN y MCP_SERVER_URL son obligatorias."
  );
}

// JWKS remoto de AuthKit — se cachea automáticamente por `jose`
const JWKS = createRemoteJWKSet(new URL(`${AUTHKIT_DOMAIN}/oauth2/jwks`));

// Header WWW-Authenticate que indica al cliente MCP dónde encontrar los metadatos
const WWW_AUTHENTICATE_HEADER = [
  'Bearer error="unauthorized"',
  'error_description="Se requiere autorización"',
  `resource_metadata="${MCP_SERVER_URL}/.well-known/oauth-protected-resource"`,
].join(", ");

// ─── Middleware de autenticación Bearer ────────────────────────────────────────
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
      audience: MCP_SERVER_URL, // debe coincidir con el Resource Indicator en el dashboard
    });

    // Podés usar los claims del token en tus tools: req.userId, req.orgId, etc.
    req.userId = payload.sub;
    req.orgId = payload.org_id;

    next();
  } catch (err) {
    console.error("Token inválido:", err.message);
    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "Token Bearer inválido o expirado." });
  }
};

// ─── App Express ───────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());

// 1. Metadatos del Resource Server (MCP spec §  Protected Resource Metadata)
//    Los clientes MCP que reciben un 401 hacen GET a este endpoint para descubrir
//    cuál es el Authorization Server (AuthKit).
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [AUTHKIT_DOMAIN],
    bearer_methods_supported: ["header"],
  });
});

// 2. Proxy de metadatos del Authorization Server (compatibilidad con clientes viejos
//    que buscan /.well-known/oauth-authorization-server directamente en el Resource Server)
app.get("/.well-known/oauth-authorization-server", async (req, res) => {
  try {
    const response = await fetch(
      `${AUTHKIT_DOMAIN}/.well-known/oauth-authorization-server`
    );
    const metadata = await response.json();
    res.json(metadata);
  } catch (err) {
    console.error("Error al obtener metadatos de AuthKit:", err.message);
    res.status(502).json({ error: "No se pudo obtener los metadatos del authorization server." });
  }
});

// ─── MCP Server factory ────────────────────────────────────────────────────────
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

// 3. Endpoint MCP — protegido con el middleware de autenticación
app.post("/mcp", bearerTokenMiddleware, async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined, // stateless
  });

  const server = createMcpServer();

  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

// ─── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`MCP server corriendo en http://localhost:${PORT}/mcp`);
  console.log(`AuthKit domain: ${AUTHKIT_DOMAIN}`);
  console.log(`MCP resource URL: ${MCP_SERVER_URL}`);
});