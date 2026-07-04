# WebSocket Rules

## WEBSOCKET_NO_AUTH
**Title:** WebSocket connection handler may be missing authentication
**Category:** websocket
**Severity:** high
**Risk:** An unauthenticated WebSocket connection can let any client subscribe to real-time data or trigger actions meant for authenticated users only.
**Recommendation:** Verify a session or token on connection (and on reconnection) before accepting subscriptions or forwarding messages.
**Standards:** OWASP Top 10: A01 Broken Access Control
