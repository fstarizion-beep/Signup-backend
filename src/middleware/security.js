const rateLimit = require("express-rate-limit");

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { message: "Too many requests. Please try again later." }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { message: "Too many authentication attempts. Please try again later." }
});

function riskCheck(req, res, next) {
  const body = req.body || {};
  const userAgent = req.get("user-agent") || "";
  const contentLength = Number(req.get("content-length") || 0);

  const suspicious =
    !userAgent ||
    userAgent.length < 8 ||
    contentLength > 20000 ||
    Object.keys(body).length > 20;

  if (suspicious) {
    return res.status(403).json({
      message: "Security check failed. Please try again normally."
    });
  }

  next();
}

module.exports = { apiLimiter, authLimiter, riskCheck };
