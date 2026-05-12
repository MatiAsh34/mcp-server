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
const AUTHKIT_DOMAIN = process.env.WORKOS_AUTHKIT_DOMAIN;
const AUTHKIT_CLIENT_ID = process.env.AUTHKIT_CLIENT_ID;
const MCP_SERVER_URL = process.env.MCP_SERVER_URL;

console.log("=== CONFIG ===");
console.log("AUTHKIT_DOMAIN:", AUTHKIT_DOMAIN);
console.log("AUTHKIT_CLIENT_ID:", AUTHKIT_CLIENT_ID);
console.log("MCP_SERVER_URL:", MCP_SERVER_URL);
console.log("================");

const JWKS = createRemoteJWKSet(
  new URL(`https://${AUTHKIT_DOMAIN}/oauth2/jwks`)
);

const WWW_AUTHENTICATE_HEADER =
  `Bearer resource_metadata="${MCP_SERVER_URL}/.well-known/oauth-protected-resource"`;

// --- Express App ---
const app = express();

app.use(express.json());

// LOG GLOBAL DE TODAS LAS REQUESTS
app.use((req, res, next) => {
  console.log("\n==============================");
  console.log("NEW REQUEST");
  console.log("TIME:", new Date().toISOString());
  console.log("METHOD:", req.method);
  console.log("URL:", req.originalUrl);
  console.log("HEADERS:", JSON.stringify(req.headers, null, 2));

  if (req.body && Object.keys(req.body).length > 0) {
    console.log("BODY:", JSON.stringify(req.body, null, 2));
  }

  console.log("==============================\n");

  next();
});

// --- Metadata Endpoints ---

app.get("/.well-known/oauth-protected-resource", (req, res) => {
  console.log(">>> HIT: oauth-protected-resource");

  const response = {
    resource: MCP_SERVER_URL,
    authorization_servers: [`https://${AUTHKIT_DOMAIN}`],
    bearer_methods_supported: ["header"],
  };

  console.log(
    "oauth-protected-resource RESPONSE:",
    JSON.stringify(response, null, 2)
  );

  res.json(response);
});

app.get("/.well-known/oauth-authorization-server", (req, res) => {
  console.log(">>> HIT: oauth-authorization-server");

  const response = {
    issuer: `https://${AUTHKIT_DOMAIN}`,
    authorization_endpoint: `https://${AUTHKIT_DOMAIN}/oauth2/authorize`,
    token_endpoint: `https://${AUTHKIT_DOMAIN}/oauth2/token`,
    jwks_uri: `https://${AUTHKIT_DOMAIN}/oauth2/jwks`,
    response_types_supported: ["code"],
    grant_types_supported: [
      "authorization_code",
      "refresh_token",
    ],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["openid", "profile", "email"],
  };

  console.log(
    "oauth-authorization-server RESPONSE:",
    JSON.stringify(response, null, 2)
  );

  res.json(response);
});

// --- Middleware Bearer Token ---
async function bearerTokenMiddleware(req, res, next) {
  console.log(">>> ENTER bearerTokenMiddleware");

  const authHeader = req.headers.authorization;

  console.log("Authorization Header:", authHeader);

  const token = authHeader?.match(/^Bearer (.+)$/)?.[1];

  if (!token) {
    console.log(">>> NO TOKEN PROVIDED");

    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "No token provided." });
  }

  console.log(">>> TOKEN FOUND");
  console.log("TOKEN PREVIEW:", token.substring(0, 40) + "...");

  try {
    console.log(">>> VERIFYING JWT");

    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://${AUTHKIT_DOMAIN}`,
    });

    console.log(">>> JWT VERIFIED SUCCESSFULLY");
    console.log("JWT PAYLOAD:", JSON.stringify(payload, null, 2));

    req.userId = payload.sub;

    next();
  } catch (err) {
    console.log(">>> JWT VERIFICATION FAILED");
    console.log("ERROR:", err);

    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "Invalid bearer token." });
  }
}

// --- Factory MCP Server ---
function createMcpServer() {
  console.log(">>> CREATING MCP SERVER");

  const server = new Server(
    { name: "postgres-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    console.log(">>> MCP: ListToolsRequestSchema");

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
    console.log(">>> MCP: CallToolRequestSchema");
    console.log(
      "REQUEST PARAMS:",
      JSON.stringify(request.params, null, 2)
    );

    if (request.params.name === executeQueryTool.name) {
      console.log(">>> EXECUTING TOOL:", executeQueryTool.name);

      const result = await executeQueryTool.handler(
        request.params.arguments
      );

      console.log(
        ">>> TOOL RESULT:",
        JSON.stringify(result, null, 2)
      );

      return result;
    }

    console.log(">>> TOOL NOT FOUND");

    throw new Error("Tool no encontrada");
  });

  return server;
}

// --- Endpoint MCP protegido POST ---
app.post("/mcp", bearerTokenMiddleware, async (req, res) => {
  console.log(">>> HIT POST /mcp");

  try {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    console.log(">>> TRANSPORT CREATED");

    const server = createMcpServer();

    console.log(">>> CONNECTING SERVER TO TRANSPORT");

    await server.connect(transport);

    console.log(">>> HANDLING MCP REQUEST");

    await transport.handleRequest(req, res, req.body);

    console.log(">>> MCP REQUEST HANDLED SUCCESSFULLY");
  } catch (err) {
    console.log(">>> ERROR IN /mcp POST");
    console.error(err);

    res.status(500).json({
      error: "Internal server error",
    });
  }
});

// --- Endpoint MCP GET ---
app.get("/mcp", bearerTokenMiddleware, async (req, res) => {
  console.log(">>> HIT GET /mcp");

  try {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    console.log(">>> TRANSPORT CREATED");

    const server = createMcpServer();

    console.log(">>> CONNECTING SERVER TO TRANSPORT");

    await server.connect(transport);

    console.log(">>> HANDLING MCP GET REQUEST");

    await transport.handleRequest(req, res);

    console.log(">>> MCP GET REQUEST HANDLED SUCCESSFULLY");
  } catch (err) {
    console.log(">>> ERROR IN /mcp GET");
    console.error(err);

    res.status(500).json({
      error: "Internal server error",
    });
  }
});

// --- Healthcheck ---
app.get("/", (req, res) => {
  console.log(">>> HIT ROOT /");

  res.json({
    ok: true,
    service: "postgres-mcp",
  });
});

// --- Iniciar servidor ---
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("\n===================================");
  console.log(`MCP server running on port ${PORT}`);
  console.log(`MCP endpoint: ${MCP_SERVER_URL}/mcp`);
  console.log("===================================\n");
});