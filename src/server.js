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
const DISABLE_AUTH = process.env.DISABLE_AUTH === "true";

const JWKS = createRemoteJWKSet(
  new URL(`${AUTHKIT_DOMAIN}/oauth2/jwks`)
);

const WWW_AUTHENTICATE_HEADER =
  `Bearer resource_metadata="${MCP_SERVER_URL}/.well-known/oauth-protected-resource"`;

const bearerTokenMiddleware = async (req, res, next) => {
  console.log("================ MCP REQUEST ================");
  console.log("Method:", req.method);
  console.log("URL:", req.originalUrl);
  console.log("Headers:", req.headers);
  console.log("Body:", req.body);

  // Claude primero hace initialize SIN Bearer token
  // Esto es normal y debe permitirse.
  if (req.body?.method === "initialize") {
    console.log("⚠️ Allowing initialize without auth");
    return next();
  }

  const token = req.headers.authorization
    ?.match(/^Bearer (.+)$/)?.[1];

  // BYPASS TEMPORAL PARA DEBUG
  if (DISABLE_AUTH) {
    console.log("⚠️ AUTH BYPASS ENABLED ⚠️");

    if (token) {
      try {
        const payload = JSON.parse(
          Buffer.from(token.split(".")[1], "base64url").toString()
        );

        console.log("JWT Payload (sin verificar):", payload);
      } catch (err) {
        console.log("No se pudo parsear JWT:", err.message);
      }
    } else {
      console.log("No Bearer token provided.");
    }

    return next();
  }

  if (!token) {
    console.log("❌ Missing Bearer token");

    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "No se proporcionó token de autorización." });
  }

  try {
    console.log("🔍 Verificando JWT...");

    const { payload } = await jwtVerify(token, JWKS, {
      issuer: AUTHKIT_DOMAIN,
      audience: MCP_SERVER_URL,
    });

    console.log("✅ JWT válido");
    console.log("JWT Payload:", payload);

    req.auth = payload;

    return next();
  } catch (err) {
    console.error("❌ Token inválido:", err);

    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "Token Bearer inválido o expirado." });
  }
};

const app = express();
app.use(express.json());

// Protected Resource Metadata
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  console.log("Serving oauth-protected-resource metadata");

  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [AUTHKIT_DOMAIN],
    bearer_methods_supported: ["header"],
  });
});

// OAuth Authorization Server Metadata proxy
app.get("/.well-known/oauth-authorization-server", async (req, res) => {
  try {
    console.log("Fetching OAuth Authorization Server metadata...");

    const response = await fetch(
      `${AUTHKIT_DOMAIN}/.well-known/oauth-authorization-server`
    );

    const metadata = await response.json();

    console.log("OAuth metadata:", metadata);

    res.json(metadata);
  } catch (err) {
    console.error(
      "Error al obtener metadatos de AuthKit:",
      err.message
    );

    res.status(502).json({
      error:
        "No se pudo obtener los metadatos del authorization server.",
    });
  }
});

function createMcpServer() {
  const server = new Server(
    {
      name: "postgres-mcp",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    console.log("📦 ListToolsRequest recibido");

    return {
      tools: [
        {
          name: executeQueryTool.name,
          description: "Ejecuta consultas SQL SELECT en PostgreSQL",
          inputSchema: {
            type: "object",
            properties: {
              query: {
                type: "string",
              },
            },
            required: ["query"],
          },
        },
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    console.log("🛠️ CallToolRequest recibido:", request);

    if (request.params.name === executeQueryTool.name) {
      return await executeQueryTool.handler(
        request.params.arguments
      );
    }

    throw new Error("Tool no encontrada");
  });

  return server;
}

app.post("/mcp", bearerTokenMiddleware, async (req, res) => {
  try {
    console.log("🚀 MCP endpoint hit");

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    const server = createMcpServer();

    await server.connect(transport);

    console.log("✅ MCP server connected to transport");

    await transport.handleRequest(req, res, req.body);

    console.log("✅ MCP request handled successfully");
  } catch (err) {
    console.error("❌ Error en /mcp:", err);

    if (!res.headersSent) {
      res.status(500).json({
        error: "Internal MCP server error",
      });
    }
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(
    `MCP server corriendo en http://localhost:${PORT}/mcp`
  );

  console.log("AUTHKIT_DOMAIN:", AUTHKIT_DOMAIN);
  console.log("MCP_SERVER_URL:", MCP_SERVER_URL);
  console.log("DISABLE_AUTH:", DISABLE_AUTH);
});