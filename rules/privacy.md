# Privacy Rules

## PRIVACY_DATA_COLLECTION_FOUND
**Title:** User data collection requires privacy disclosure
**Category:** privacy
**Severity:** medium
**Risk:** Collected personal data, AI prompts, analytics, and payment metadata need clear privacy policy disclosure and retention controls.
**Recommendation:** Review the generated data inventory and publish a lawyer-reviewed privacy policy before public launch.
**Standards:** Privacy by Design; OWASP ASVS V14 Configuration

## PRIVACY_NO_DELETION_ENDPOINT
**Title:** User data is collected but no account/data deletion path was found
**Category:** privacy
**Severity:** medium
**Risk:** GDPR, CCPA, and similar regulations require a way for users to request deletion of their personal data; without one, the app cannot honor erasure requests.
**Recommendation:** Add an account deletion flow (self-service or support-triggered) that removes or anonymizes personal data across all data stores.
**Standards:** GDPR Article 17 Right to Erasure; CCPA Right to Delete

## PRIVACY_THIRD_PARTY_TRACKING_NO_CONSENT
**Title:** Analytics or tracking script found without a visible consent mechanism
**Category:** privacy
**Severity:** medium
**Risk:** Loading analytics, ads, or session-replay scripts before obtaining consent can violate GDPR/ePrivacy and similar cookie-consent requirements.
**Recommendation:** Gate non-essential tracking scripts behind a cookie consent banner and only load them after opt-in where required.
**Standards:** GDPR; ePrivacy Directive
