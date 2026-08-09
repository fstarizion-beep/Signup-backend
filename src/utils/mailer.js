const nodemailer = require("nodemailer");

function getTransporter() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    return null;
  }

  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE).toLowerCase() === "true",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

async function sendVerificationEmail(to, code) {
  const transporter = getTransporter();
  if (!transporter) {
    console.log(`[DEV] Verification code for ${to}: ${code}`);
    return;
  }

  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject: "STARIZION email verification code",
    text: `Your STARIZION verification code is ${code}. It expires in ${process.env.VERIFICATION_CODE_MINUTES || 10} minutes.`
  });
}

async function sendResetEmail(to, token) {
  const transporter = getTransporter();
  const resetUrl = `${process.env.FRONTEND_URL || "http://localhost:3000"}/reset-password?token=${token}&email=${encodeURIComponent(to)}`;

  if (!transporter) {
    console.log(`[DEV] Password reset link for ${to}: ${resetUrl}`);
    return;
  }

  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject: "STARIZION password reset",
    text: `Reset your STARIZION password using this link: ${resetUrl}`
  });
}

module.exports = { sendVerificationEmail, sendResetEmail };
