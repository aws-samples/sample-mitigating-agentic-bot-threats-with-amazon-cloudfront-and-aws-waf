// Calls to the Lambda@Edge liveness API. Session state lives in HttpOnly
// cookies; the page never sees or sends a session token itself.
async function post(path) {
  try {
    const response = await fetch(path, {
      method: 'POST',
      // A JSON content type forces a CORS preflight for any cross-origin caller.
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
      credentials: 'same-origin',
      cache: 'no-store',
    });
    // AWS WAF Challenge (202) and CAPTCHA (405) responses carry this header.
    // A POST can't run their interstitials, so the page sends the user back.
    if (response.headers.get('x-amzn-waf-action')) {
      return { ok: false, status: response.status, data: { error: 'waf_challenge' } };
    }
    // The liveness API always answers with JSON. Anything else came from in
    // front of it: an AWS WAF block (403) or a CloudFront error page (5xx).
    if (!(response.headers.get('content-type') || '').includes('application/json')) {
      const error = response.status === 403 ? 'request_blocked' : 'verification_unavailable';
      return { ok: false, status: response.status, data: { error } };
    }
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, data };
  } catch {
    return { ok: false, status: 0, data: {} };
  }
}

export const createLivenessSession = () => post('/liveness/session');
export const verifyLivenessSession = () => post('/liveness/verify');
