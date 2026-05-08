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
const MCP_SERVER_URL = process.env.MCP_SERVER_URL;

const JWKS = createRemoteJWKSet(new URL(`${AUTHKIT_DOMAIN}/oauth2/jwks`));

const WWW_AUTHENTICATE_HEADER = [
  'Bearer error="unauthorized"',
  'error_description="Se requiere autorización"',
  `resource_metadata="${MCP_SERVER_URL}/.well-known/oauth-protected-resource"`,
].join(", ");

const bearerTokenMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.match(/^Bearer (.+)$/)?.[1];

  if (!token) {
    console.error("Authorization header recibido:", req.headers.authorization);
    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "No se proporcionó token de autorización." });
  }
  
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: AUTHKIT_DOMAIN,
      audience: "client_01KQW6AAJ4X9RCYBJWTF4HBQ54",
    });
    console.log("JWT payload:", JSON.stringify(payload));
    next();
  } catch (err) {
    console.error("JWT error:", err.code, err.message);
    console.error("Token recibido:", token.substring(0, 50) + "...");
    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "Token Bearer inválido o expirado." });
  }
  
};

const app = express();
app.use(express.json());

app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    console.log(`${req.method.padEnd(6)} ${req.path.padEnd(45)} -> ${res.statusCode} (${Date.now() - start}ms)`);
  });
  next();
});

const oauthProtectedResource = (req, res) => {
  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [AUTHKIT_DOMAIN],
    bearer_methods_supported: ["header"],
  });
};

const oauthAuthorizationServer = async (req, res) => {
  try {
    const response = await fetch(`${AUTHKIT_DOMAIN}/.well-known/oauth-authorization-server`);
    const metadata = await response.json();
    res.json(metadata);
  } catch (err) {
    console.error("Error al obtener metadatos de AuthKit:", err.message);
    res.status(502).json({ error: "No se pudo obtener los metadatos del authorization server." });
  }
};

// Reemplaza los dos app.get anteriores con estos cuatro:
app.get("/.well-known/oauth-protected-resource", oauthProtectedResource);
app.get("/mcp/.well-known/oauth-protected-resource", oauthProtectedResource);
app.get("/.well-known/oauth-authorization-server", oauthAuthorizationServer);
app.get("/mcp/.well-known/oauth-authorization-server", oauthAuthorizationServer);

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

app.post("/", bearerTokenMiddleware, async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });
  const server = createMcpServer();
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`MCP server corriendo en http://localhost:${PORT}/mcp`);
});
