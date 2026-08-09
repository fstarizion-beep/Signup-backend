import crypto from "crypto";

export function hashValue(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function randomCode() {
  return String(crypto.randomInt(100000, 1000000));
}

export function randomToken() {
  return crypto.randomBytes(32).toString("hex");
}
