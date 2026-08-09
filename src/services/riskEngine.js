/*
  STARIZION mini-server risk layer.

  This is deliberately server-side and deterministic. It provides the first
  security gate; an external AI/risk provider or CAPTCHA can be added later
  without trusting the browser with secrets.

  Returns: allow | review | block
*/

export function assessRequest(req, payload = {}) {
  const userAgent = String(req.get("user-agent") || "").toLowerCase();
  const signals = [];

  if (!userAgent || userAgent.length < 8) signals.push("missing_user_agent");
  if (/curl|wget|python-requests|scrapy|headlesschrome|phantomjs/.test(userAgent)) {
    signals.push("automation_user_agent");
  }

  const completionSeconds = Number(req.get("x-form-completion-seconds") || 0);
  if (completionSeconds > 0 && completionSeconds < 2) {
    signals.push("impossibly_fast_form");
  }

  // Honeypot: frontend should render this field hidden. Humans should leave it empty.
  if (payload.website || payload.companyWebsite) {
    signals.push("honeypot_triggered");
  }

  if (signals.includes("honeypot_triggered") || signals.includes("automation_user_agent")) {
    return { action: "block", score: 100, signals };
  }

  if (signals.length >= 2) {
    return { action: "review", score: 70, signals };
  }

  return { action: "allow", score: 0, signals };
}
