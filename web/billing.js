import { Purchases } from "/assets/vendor/purchases-js.esm.js";

const statusEl = document.querySelector("#billing-status");
const actionsEl = document.querySelector("#billing-actions");
const paywallEl = document.querySelector("#revenuecat-paywall");
const plan = document.querySelector(".billing-shell")?.dataset.plan || "pro";

main().catch((error) => {
  setStatus(error.message || "RevenueCat checkout could not be loaded.");
  showRetry();
});

async function main() {
  if (!statusEl || !actionsEl || !paywallEl) return;

  const configResponse = await fetch("/api/billing/config");
  if (!configResponse.ok) {
    setStatus("Please sign in again before starting checkout.");
    return;
  }

  const config = await configResponse.json();
  if (!config.apiKey) {
    setStatus("RevenueCat API key is missing.");
    return;
  }

  const purchases = Purchases.configure({
    apiKey: config.apiKey,
    appUserId: config.appUserId,
  });

  setStatus("Checking your subscription...");
  const customerInfo = await purchases.getCustomerInfo();
  if (customerInfo.entitlements?.active?.[config.entitlementId]) {
    setStatus("Your subscription is already active.");
    actionsEl.innerHTML = `<a class="button button-primary" href="/dashboard">Return to dashboard</a>`;
    return;
  }

  actionsEl.innerHTML = `<button class="button button-primary" id="open-paywall" type="button">Open checkout</button>`;
  setStatus("Ready to continue.");

  document.querySelector("#open-paywall")?.addEventListener("click", async () => {
    try {
      setStatus("Opening RevenueCat checkout...");
      actionsEl.innerHTML = "";

      const offerings = await purchases.getOfferings();
      const offering = config.offeringId
        ? offerings.all?.[config.offeringId]
        : offerings.current;

      if (!offering) {
        setStatus(
          config.offeringId
            ? `RevenueCat offering "${config.offeringId}" was not found.`
            : "RevenueCat has no current offering configured.",
        );
        showRetry();
        return;
      }

      const configuredPackageId = config.packages?.[plan];
      const rcPackage =
        configuredPackageId && offering?.packagesById?.[configuredPackageId]
          ? offering.packagesById[configuredPackageId]
          : null;

      if (configuredPackageId && !rcPackage) {
        setStatus(`RevenueCat package "${configuredPackageId}" was not found in this offering.`);
        showRetry();
        return;
      }

      const purchaseResult = rcPackage
        ? await purchases.purchase({
            rcPackage,
            customerEmail: config.customerEmail,
            htmlTarget: paywallEl,
            metadata: { source: "gravel_dashboard", plan },
          })
        : await purchases.presentPaywall({
            htmlTarget: paywallEl,
            offering,
            customerEmail: config.customerEmail,
          });

      const active = purchaseResult.customerInfo?.entitlements?.active || {};
      if (active[config.entitlementId] || Object.keys(active).length > 0) {
        setStatus("Subscription active. Returning to your dashboard...");
        window.setTimeout(() => {
          window.location.href = "/dashboard";
        }, 1000);
        return;
      }

      setStatus("Checkout finished, but no active entitlement was found yet.");
      actionsEl.innerHTML = `<a class="button button-primary" href="/dashboard">Return to dashboard</a>`;
    } catch (error) {
      setStatus(error.message || "RevenueCat checkout could not be opened.");
      showRetry();
    }
  });
}

function setStatus(message) {
  if (statusEl) statusEl.textContent = message;
}

function showRetry() {
  if (!actionsEl) return;

  actionsEl.innerHTML = `
    <button class="button button-primary" type="button" onclick="window.location.reload()">Try again</button>
    <a class="button button-secondary" href="/dashboard">Back to dashboard</a>
  `;
}
