import { config } from "dotenv";
config({ path: ".env.local" });

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import { randomUUID } from "node:crypto";
import cors from "cors";

const app = createMcpExpressApp({
  host: "0.0.0.0",
  allowedHosts: ["localhost", "127.0.0.1", "192.168.1.165"],
});

// Enable CORS for all routes
app.use(
  cors({
    origin: true, // Allow all origins (or specify specific origins)
    credentials: true,
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "mcp-session-id",
      "last-event-id",
    ],
  }),
);

// Request logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  const timestamp = new Date().toISOString();
  console.log(`\n${"=".repeat(80)}`);
  console.log(`[${timestamp}] ${req.method} ${req.url}`);
  console.log(`${"=".repeat(80)}`);
  console.log("Headers:", JSON.stringify(req.headers, null, 2));

  if (req.body && Object.keys(req.body).length > 0) {
    console.log("Body:", JSON.stringify(req.body, null, 2));
  }

  const originalSend = res.send;
  res.send = function (data: any) {
    console.log(`Response Status: ${res.statusCode}`);
    console.log(`${"=".repeat(80)}\n`);
    return originalSend.call(this, data);
  };

  next();
});

// Azure AD Configuration
const tenantId = process.env.AZURE_TENANT_ID || "";
const clientId = process.env.AZURE_CLIENT_ID || "";
const audience = `api://${clientId}`;

// JWKS client to fetch public keys from Azure AD
const client = jwksClient({
  jwksUri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
  cache: true,
  cacheMaxAge: 86400000,
});

function getKey(header: jwt.JwtHeader, callback: jwt.SigningKeyCallback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err);
      return;
    }
    const signingKey = key?.getPublicKey();
    callback(null, signingKey);
  });
}

// Azure AD Authentication Middleware
async function authenticateAzureAD(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  console.log("\n🔐 Starting authentication...");
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log(
      "❌ Authentication failed: Missing or invalid authorization header",
    );
    res.status(401).json({ error: "Missing or invalid authorization header" });
    return;
  }

  const token = authHeader.substring(7);
  console.log(
    "📝 Token received (first 20 chars):",
    token.substring(0, 20) + "...",
  );

  try {
    jwt.verify(
      token,
      getKey,
      {
        audience: audience,
        issuer: `https://sts.windows.net/${tenantId}/`,
        algorithms: ["RS256"],
      },
      (err, decoded) => {
        if (err) {
          console.log("❌ Token validation failed:", err.message);
          console.log("   Expected audience:", audience);
          console.log(
            "   Expected issuer:",
            `https://sts.windows.net/${tenantId}/`,
          );
          res.status(401).json({
            error: "Invalid token",
            details: err.message,
          });
          return;
        }

        console.log("✅ Token validated successfully!");
        console.log("   Token claims:", JSON.stringify(decoded, null, 2));
        (req as any).user = decoded;
        next();
      },
    );
  } catch (error) {
    console.log("❌ Authentication error:", error);
    res.status(401).json({ error: "Authentication failed" });
  }
}

// Create MCP Server instance
const getServer = () => {
  const server = new McpServer(
    {
      name: "azure-ad-mcp-server",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  // Register tools using the new API
  server.registerTool(
    "echo",
    {
      description: "Echoes back the input text",
      inputSchema: {
        message: { type: "string", description: "The message to echo" },
      },
    },
    async ({ message }) => {
      return {
        content: [
          {
            type: "text",
            text: `Echo: ${message}`,
          },
        ],
      };
    },
  );

  server.registerTool(
    "get_time",
    {
      description: "Returns the current server time",
      inputSchema: {},
    },
    async () => {
      return {
        content: [
          {
            type: "text",
            text: `Current server time: ${new Date().toISOString()}`,
          },
        ],
      };
    },
  );

  return server;
};

// Map to store transports by session ID
const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

// MCP POST endpoint
app.post("/mcp", authenticateAzureAD, async (req: Request, res: Response) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;

  if (sessionId) {
    console.log(`\n📨 MCP POST for session: ${sessionId}`);
  } else {
    console.log("\n📨 MCP POST (new session)");
  }

  try {
    let transport: StreamableHTTPServerTransport;

    if (sessionId && transports[sessionId]) {
      console.log("   ♻️  Reusing existing transport");
      transport = transports[sessionId];
    } else if (!sessionId && isInitializeRequest(req.body)) {
      console.log("   🆕 Creating new transport");

      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (newSessionId: string) => {
          console.log(`   ✅ Session initialized: ${newSessionId}`);
          transports[newSessionId] = transport;
        },
      });

      transport.onclose = () => {
        const sid = transport.sessionId;
        if (sid && transports[sid]) {
          console.log(`   🔌 Session closed: ${sid}`);
          delete transports[sid];
        }
      };

      const server = getServer();
      await server.connect(transport);

      await transport.handleRequest(req, res, req.body);
      console.log("   ✅ Initialization complete");
      return;
    } else {
      console.log("   ❌ Invalid request");
      res.status(400).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Bad Request: No valid session ID" },
        id: null,
      });
      return;
    }

    await transport.handleRequest(req, res, req.body);
    console.log("   ✅ Request complete");
  } catch (error) {
    console.error("   ❌ Error:", error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null,
      });
    }
  }
});

// MCP GET endpoint (SSE)
app.get("/mcp", authenticateAzureAD, async (req: Request, res: Response) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;

  if (!sessionId || !transports[sessionId]) {
    console.log("   ❌ Invalid session for SSE");
    res.status(400).send("Invalid or missing session ID");
    return;
  }

  console.log(`\n📡 SSE for session ${sessionId}`);
  const transport = transports[sessionId];
  await transport.handleRequest(req, res);
});

// MCP DELETE endpoint
app.delete("/mcp", authenticateAzureAD, async (req: Request, res: Response) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;

  if (!sessionId || !transports[sessionId]) {
    res.status(400).send("Invalid or missing session ID");
    return;
  }

  console.log(`\n🗑️  DELETE session ${sessionId}`);
  const transport = transports[sessionId];
  await transport.handleRequest(req, res);
});

// OAuth discovery endpoints
app.get(
  "/.well-known/oauth-authorization-server",
  (req: Request, res: Response) => {
    res.json({
      issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
      authorization_endpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
      token_endpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
      jwks_uri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
      response_types_supported: ["code", "token", "id_token"],
      subject_types_supported: ["pairwise"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: [
        "openid",
        "profile",
        "email",
        `api://${clientId}/.default`,
      ],
      token_endpoint_auth_methods_supported: [
        "client_secret_post",
        "client_secret_basic",
      ],
      claims_supported: ["sub", "iss", "aud", "exp", "iat", "name", "email"],
    });
  },
);

app.get(
  "/.well-known/oauth-protected-resource",
  (req: Request, res: Response) => {
    const baseUrl =
      process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
    res.json({
      resource: `api://${clientId}`,
      authorization_servers: [
        `https://login.microsoftonline.com/${tenantId}/v2.0`,
      ],
      bearer_methods_supported: ["header"],
      resource_signing_alg_values_supported: ["RS256"],
      resource_documentation: `${baseUrl}/`,
      // Additional fields that some clients may expect (non-standard)
      authorization_endpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
      token_endpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    });
  },
);

app.get("/health", (req: Request, res: Response) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

app.get("/", (req: Request, res: Response) => {
  const baseUrl =
    process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
  res.json({
    name: "Azure AD MCP Server",
    version: "1.0.0",
    endpoints: {
      mcp: "/mcp",
      health: "/health",
      oauth_discovery: "/.well-known/oauth-authorization-server",
      protected_resource_metadata: "/.well-known/oauth-protected-resource",
    },
    authentication: {
      type: "oauth2",
      authorization_server_metadata: `${baseUrl}/.well-known/oauth-authorization-server`,
      protected_resource_metadata: `${baseUrl}/.well-known/oauth-protected-resource`,
    },
  });
});

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";

app.listen(PORT, HOST, () => {
  console.log("\n" + "=".repeat(80));
  console.log("🚀 Azure AD MCP Server Started");
  console.log("=".repeat(80));
  console.log(`📍 Listening on: ${HOST}:${PORT}`);
  console.log(`📍 Access via: http://localhost:${PORT}`);
  console.log(`\n📡 Endpoints:`);
  console.log(`   • MCP (POST/GET/DELETE): http://localhost:${PORT}/mcp`);
  console.log(`   • Health check:          http://localhost:${PORT}/health`);
  console.log(
    `   • OAuth discovery:       http://localhost:${PORT}/.well-known/oauth-authorization-server`,
  );
  console.log(
    `   • Resource metadata:     http://localhost:${PORT}/.well-known/oauth-protected-resource`,
  );
  console.log(`\n🔐 Azure AD Configuration:`);
  console.log(`   • Tenant ID:  ${tenantId}`);
  console.log(`   • Client ID:  ${clientId}`);
  console.log(`   • Audience:   ${audience}`);
  console.log("=".repeat(80) + "\n");
  console.log("💡 Waiting for requests...\n");
});

// Cleanup on shutdown
process.on("SIGINT", async () => {
  console.log("\n\nShutting down...");
  for (const sessionId in transports) {
    try {
      await transports[sessionId].close();
      delete transports[sessionId];
    } catch (error) {
      console.error(`Error closing session ${sessionId}:`, error);
    }
  }
  console.log("Shutdown complete");
  process.exit(0);
});
