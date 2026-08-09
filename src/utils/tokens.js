const crypto = require("crypto");

function sixDigitCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function hashToken(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function randomToken() {
  return crypto.randomBytes(32).toString("hex");
}

module.exports = { sixDigitCode, hashToken, randomToken };
