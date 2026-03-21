// E2E Test Echo Server
// Returns request metadata so tests can verify traffic reached the backend
// through the QURL/NHP system.

export const handler = async (event) => {
  const headers = event.headers || {};
  const now = new Date().toISOString();

  const body = {
    service: "layerv-e2e-echo",
    timestamp: now,
    request: {
      method: event.requestContext?.http?.method || "UNKNOWN",
      path: event.rawPath || "/",
      query: event.rawQueryString || "",
      source_ip: event.requestContext?.http?.sourceIp || "unknown",
      user_agent: headers["user-agent"] || "",
    },
    headers: {
      host: headers["host"] || "",
      // NHP-injected headers (set by Traefik after auth)
      "x-forwarded-for": headers["x-forwarded-for"] || "",
      "x-real-ip": headers["x-real-ip"] || "",
      "x-request-id": headers["x-request-id"] || "",
      // Cookie presence (don't echo values for security)
      has_nhp_token: (headers["cookie"] || "").includes("nhp_token"),
    },
    // Fingerprint for test assertions
    echo_id: `echo-${Date.now()}`,
  };

  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json",
      "X-Echo-Service": "layerv-e2e",
      "Cache-Control": "no-store",
    },
    body: JSON.stringify(body, null, 2),
  };
};
