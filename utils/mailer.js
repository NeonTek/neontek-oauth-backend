const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || "587", 10),
  secure: Number(process.env.SMTP_PORT) === 465,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendMail({ to, subject, text, html }) {
  const from = process.env.EMAIL_FROM || "NeonTek <no-reply@neontek.co.ke>";
  const info = await transporter.sendMail({ from, to, subject, text, html });
  console.log("Email sent:", info.messageId);
  return info;
}

module.exports = { sendMail };
