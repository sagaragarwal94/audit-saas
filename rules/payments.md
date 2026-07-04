# Payments Rules

## PAYMENT_STRIPE_WEBHOOK_SIGNATURE_MISSING
**Title:** Stripe webhook may not verify event signatures
**Category:** payments
**Severity:** critical
**Risk:** Attackers may forge payment events and unlock paid features or alter subscription state.
**Recommendation:** Use `stripe.webhooks.constructEvent` with the raw request body and webhook signing secret before processing events.
**Code Example:** const event = stripe.webhooks.constructEvent(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET);
**Standards:** OWASP API Security: Unrestricted Access to Sensitive Business Flows

## PAYMENT_IDEMPOTENCY_MISSING
**Title:** Payment webhook may be missing idempotency handling
**Category:** payments
**Severity:** high
**Risk:** Repeated webhook delivery can duplicate side effects, corrupt subscription state, or issue duplicate credits.
**Recommendation:** Store processed event IDs and make subscription updates idempotent.
**Standards:** OWASP API Security: Unrestricted Access to Sensitive Business Flows

## STRIPE_CLIENT_TRUSTED_AMOUNT
**Title:** Checkout may trust a price or amount value sent from the client
**Category:** payments
**Severity:** critical
**Risk:** If a checkout or payment-intent handler reads the amount or price directly from the request body, a user can tamper with it client-side and pay any amount they choose.
**Recommendation:** Always look up the price/amount server-side from a fixed price ID or your own product catalog — never trust a client-submitted amount.
**Standards:** OWASP API Security: Unrestricted Access to Sensitive Business Flows
