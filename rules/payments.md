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
