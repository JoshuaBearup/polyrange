// Web Messaging — canonical exploit loads the page with the canary as the
// query param; page's vulnerable postMessage handler writes it to
// window.__pr_marker; the browser oracle's __pr_marker check finds it.
export const defences = {
  0: {
    canonicalPayload: (canary) => canary,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
