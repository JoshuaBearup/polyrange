// Per-deploy infra-variant anchor for the two halves of WSTG-INPV-15.
//
// splitting  — response-splitting via CRLF injection in a single-process Node
//              deploy (default behaviour, runs the standard runtime).
// smuggling  — request smuggling via CL/TE desync between an HAProxy frontend
//              and a raw-net Node backend, both in one container.
//
// POLYRANGE_HTTP_INFRA pins the variant for per-variant validation; otherwise
// a uniform pick spreads coverage.

const VARIANTS = ['splitting', 'smuggling']

export function pickAnchor() {
  const pin = process.env.POLYRANGE_HTTP_INFRA
  const variant = (pin && VARIANTS.includes(pin)) ? pin : VARIANTS[Math.floor(Math.random() * VARIANTS.length)]
  if (variant === 'smuggling') {
    return {
      infraVariant: 'smuggling',
      note: 'Build the request-smuggling half. Set scenario.infraVariant to "smuggling". The deploy runs HAProxy as a frontend in front of a raw-net Node backend; CL/TE desync against the pair surfaces the canary from a privileged backend endpoint whose access control trusts a frontend-added upstream header.',
    }
  }
  return {
    infraVariant: 'splitting',
    note: 'Build the response-splitting half. Set scenario.infraVariant to "splitting". The deploy is single-process Node; CRLF injection in a header-building sink terminates the legitimate header block and surfaces a trailing internal-token header as response body bytes.',
  }
}
