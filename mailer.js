'use strict';
/**
 * mailer.js: Zero-dependency Resend REST API client ($0.00 free tier: 3,000 emails/mo).
 * Uses Node 20+ built-in fetch. Falls back to console + Admin Live OTP Log when RESEND_API_KEY is not configured.
 */
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const MAIL_FROM = process.env.MAIL_FROM || 'MZTRADER <security@mztrader.com>';
const PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN || 'http://127.0.0.1:3000';

const escapeHtml = (str) => String(str ?? '')
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

async function sendEmail({ to, subject, text, html }) {
  if (!RESEND_API_KEY) {
    console.log(`\n[MZTRADER MAILER - DEV/FREE MODE] To: ${to} | Subject: ${subject}\n${text}\n`);
    return { deliveredVia: 'console-and-admin-log' };
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from: MAIL_FROM, to: [to], subject, text, html }),
  });

  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    console.error(`Resend API error (${res.status}): ${detail}`);
  }
  return { deliveredVia: 'resend' };
}

module.exports = {
  async sendDeviceCode(to, code, { deviceLabel, ip }) {
    const safeLabel = escapeHtml(deviceLabel);
    const safeIp = escapeHtml(ip);
    await sendEmail({
      to,
      subject: `MZTRADER: ${code} هو كود التحقق الخاص بك`,
      text: `كود التحقق لإضافة الجهاز "${deviceLabel}" (IP: ${ip}) على MZTRADER هو: ${code}. صالح لمدة 10 دقائق.`,
      html: `
        <div dir="rtl" style="font-family:sans-serif;line-height:1.6;">
          <h2>MZTRADER</h2>
          <p>كود التحقق لتسجيل الجهاز <strong>${safeLabel}</strong> (IP: <code>${safeIp}</code>) هو:</p>
          <p style="font-size:28px;font-weight:700;letter-spacing:4px;margin:16px 0;color:#E50914;">${escapeHtml(code)}</p>
          <p>ينتهي هذا الكود خلال 10 دقائق. إذا لم تكن أنت من حاول تسجيل الدخول، يرجى تغيير كلمة المرور فوراً.</p>
        </div>
      `,
    });
  },

  async sendNewDeviceAlert(to, { deviceLabel, ip, replaced }) {
    const safeLabel = escapeHtml(deviceLabel);
    const safeIp = escapeHtml(ip);
    const actionText = replaced ? 'استبدل جهازاً سابقاً وتمت إضافته إلى' : 'تمت إضافته إلى';
    const devicesUrl = `${PUBLIC_ORIGIN}/portal`;
    await sendEmail({
      to,
      subject: `MZTRADER: تنبيه إضافة جهاز جديد (${deviceLabel})`,
      text: `جهاز جديد ("${deviceLabel}"، IP: ${ip}) ${actionText} حسابك في MZTRADER.\n\nإدارة أجهزتك: ${devicesUrl}`,
      html: `
        <div dir="rtl" style="font-family:sans-serif;line-height:1.6;">
          <h2>MZTRADER</h2>
          <p>جهاز جديد (<strong>${safeLabel}</strong>، IP: <code>${safeIp}</code>) ${actionText} حسابك.</p>
          <p>يمكنك مراجعة أجهزتك المسجلة من داخل بوابة المشتركين: <a href="${escapeHtml(devicesUrl)}">${escapeHtml(devicesUrl)}</a></p>
        </div>
      `,
    });
  },

  async sendStepUpCode(to, code) {
    await sendEmail({
      to,
      subject: `MZTRADER: ${code} — تأكيد هوية الحساب`,
      text: `يرجى تأكيد هويتك على MZTRADER بإدخال الكود المكون من 6 أرقام: ${code}. صالح لمدة 10 دقائق.`,
      html: `
        <div dir="rtl" style="font-family:sans-serif;line-height:1.6;">
          <h2>MZTRADER</h2>
          <p>يرجى تأكيد هويتك بإدخال كود التحقق المكون من 6 أرقام:</p>
          <p style="font-size:28px;font-weight:700;letter-spacing:4px;margin:16px 0;color:#E50914;">${escapeHtml(code)}</p>
          <p>ينتهي هذا الكود خلال 10 دقائق.</p>
        </div>
      `,
    });
  },
};
