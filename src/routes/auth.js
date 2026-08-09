import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import { authLimiter } from "../middleware/rateLimit.js";
import { assessRequest } from "../services/riskEngine.js";
import { hashValue, randomCode, randomToken } from "../services/security.js";
import { sendCodeEmail } from "../services/mailer.js";

const router = express.Router();

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function clean(value) {
  return typeof value === "string" ? value.trim() : "";
}

function validatePassword(password) {
  return typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 128;
}

function signToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), username: user.username, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function publicUser(user) {
  return {
    id: user._id,
    firstName: user.firstName,
    lastName: user.lastName,
    username: user.username,
    email: user.email,
    phoneNumber: user.phoneNumber,
    country: user.country,
    isVerified: user.isVerified
  };
}

function securityGate(req, payload) {
  const result = assessRequest(req, payload);
  if (result.action === "block") {
    const error = new Error("Security check failed.");
    error.status = 403;
    throw error;
  }
  return result;
}

router.post("/signup", authLimiter, async (req, res, next) => {
  try {
    securityGate(req, req.body);

    const {
      firstName, lastName, username, email,
      phoneNumber, country, password, confirmPassword
    } = req.body;

    const first = clean(firstName);
    const last = clean(lastName);
    const userName = clean(username).toLowerCase();
    const mail = clean(email).toLowerCase();
    const phone = clean(phoneNumber);
    const nation = clean(country);

    if (!first || !last || !userName || !mail || !phone || !nation || !password || !confirmPassword) {
      return res.status(400).json({ success: false, message: "All signup fields are required." });
    }

    if (!emailRegex.test(mail)) {
      return res.status(400).json({ success: false, message: "Enter a valid email address." });
    }

    if (!/^[a-z0-9_]{3,30}$/.test(userName)) {
      return res.status(400).json({ success: false, message: "Username must be 3-30 characters using letters, numbers or underscores." });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ success: false, message: "Password must be 8-128 characters." });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: "Passwords do not match." });
    }

    const existing = await User.findOne({
      $or: [{ email: mail }, { username: userName }]
    });

    if (existing) {
      const sameEmail = existing.email === mail;
      return res.status(409).json({
        success: false,
        message: sameEmail ? "An account with this email already exists." : "That username is already taken."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const code = randomCode();

    const user = await User.create({
      firstName: first,
      lastName: last,
      username: userName,
      email: mail,
      phoneNumber: phone,
      country: nation,
      passwordHash,
      verificationCodeHash: hashValue(code),
      verificationCodeExpires: new Date(Date.now() + 10 * 60 * 1000)
    });

    await sendCodeEmail({ to: mail, code, purpose: "verification" });

    res.status(201).json({
      success: true,
      message: "Account created. Check your email for the 6-digit verification code.",
      userId: user._id,
      requiresVerification: true
    });
  } catch (error) {
    next(error);
  }
});

router.post("/verify-email", authLimiter, async (req, res, next) => {
  try {
    const email = clean(req.body.email).toLowerCase();
    const code = clean(req.body.code);

    if (!emailRegex.test(email) || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ success: false, message: "Enter a valid email and 6-digit code." });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ success: false, message: "Invalid verification details." });

    if (user.isVerified) {
      return res.status(200).json({ success: true, message: "Account is already verified." });
    }

    if (!user.verificationCodeExpires || user.verificationCodeExpires < new Date()) {
      return res.status(400).json({ success: false, message: "Verification code has expired." });
    }

    if (hashValue(code) !== user.verificationCodeHash) {
      return res.status(400).json({ success: false, message: "Invalid verification code." });
    }

    user.isVerified = true;
    user.verificationCodeHash = null;
    user.verificationCodeExpires = null;
    user.updatedAt = new Date();
    await user.save();

    const token = signToken(user);
    res.json({ success: true, message: "Email verified successfully.", token, user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

router.post("/resend-code", authLimiter, async (req, res, next) => {
  try {
    const email = clean(req.body.email).toLowerCase();
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: "Enter a valid email address." });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: "Account not found." });
    if (user.isVerified) return res.json({ success: true, message: "Account is already verified." });

    const code = randomCode();
    user.verificationCodeHash = hashValue(code);
    user.verificationCodeExpires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    await sendCodeEmail({ to: email, code, purpose: "verification" });
    res.json({ success: true, message: "A new verification code has been sent." });
  } catch (error) {
    next(error);
  }
});

router.post("/login", authLimiter, async (req, res, next) => {
  try {
    securityGate(req, req.body);

    const identifier = clean(req.body.identifier).toLowerCase();
    const password = req.body.password;

    if (!identifier || !password) {
      return res.status(400).json({ success: false, message: "Email/username and password are required." });
    }

    const user = await User.findOne({
      $or: [{ email: identifier }, { username: identifier }]
    });

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ success: false, message: "Invalid login details." });
    }

    if (!user.isVerified) {
      return res.status(403).json({
        success: false,
        message: "Please verify your email before logging in.",
        requiresVerification: true
      });
    }

    const token = signToken(user);
    res.json({ success: true, message: "Login successful.", token, user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

router.post("/forgot-password", authLimiter, async (req, res, next) => {
  try {
    const email = clean(req.body.email).toLowerCase();

    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: "Enter a valid email address." });
    }

    const user = await User.findOne({ email });

    // Generic response reduces account enumeration.
    if (!user) {
      return res.json({ success: true, message: "If an account exists, a reset code has been sent." });
    }

    const token = randomToken();
    user.resetTokenHash = hashValue(token);
    user.resetTokenExpires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    await sendCodeEmail({ to: email, code: token, purpose: "password reset" });
    res.json({ success: true, message: "If an account exists, a reset code has been sent." });
  } catch (error) {
    next(error);
  }
});

router.post("/reset-password", authLimiter, async (req, res, next) => {
  try {
    const email = clean(req.body.email).toLowerCase();
    const resetToken = clean(req.body.resetToken);
    const newPassword = req.body.newPassword;

    if (!emailRegex.test(email) || !resetToken || !validatePassword(newPassword)) {
      return res.status(400).json({ success: false, message: "Invalid reset details." });
    }

    const user = await User.findOne({
      email,
      resetTokenHash: hashValue(resetToken),
      resetTokenExpires: { $gt: new Date() }
    });

    if (!user) return res.status(400).json({ success: false, message: "Invalid or expired reset code." });

    user.passwordHash = await bcrypt.hash(newPassword, 12);
    user.resetTokenHash = null;
    user.resetTokenExpires = null;
    user.updatedAt = new Date();
    await user.save();

    res.json({ success: true, message: "Password reset successfully." });
  } catch (error) {
    next(error);
  }
});

router.get("/me", async (req, res, next) => {
  try {
    const header = req.get("authorization") || "";
    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, message: "Authentication required." });
    }

    const token = header.slice(7);
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(payload.sub);

    if (!user) return res.status(401).json({ success: false, message: "User not found." });

    res.json({ success: true, user: publicUser(user) });
  } catch {
    res.status(401).json({ success: false, message: "Invalid or expired token." });
  }
});

export default router;
