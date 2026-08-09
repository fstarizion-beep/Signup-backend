import nodemailer from "nodemailer";

function configured() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

export async function sendCodeEmail({ to, code, purpose }) {
  if (!configured()) {
    console.log(`[STARIZION DEV] ${purpose} code for ${to}: ${code}`);
    return;
  }

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT || 587) === 465,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });

  await transporter.sendMail({
    from: process.env.EMAIL_FROM || process.env.SMTP_USER,
    to,
    subject: purpose === "verification" ? "STARIZION verification code" : "STARIZION password reset code",
    text: `Your STARIZION ${purpose} code is ${code}. It expires in 10 minutes.`
  });
}
