'use strict';
/**
 * mailer.js: Zero-dependency transactional email client over HTTPS (port 443, Koyeb-safe).
 * Supports free tiers with zero credit card:
 *   1. Resend  (RESEND_API_KEY)  — $0 / 3,000 emails per month (100/day)
 *   2. Brevo   (BREVO_API_KEY)   — $0 / 300 emails per day (~9,000/mo)
 *   3. Mailjet (MAILJET_API_KEY + MAILJET_SECRET_KEY) — $0 / 6,000 emails per month (200/day)
 * Uses Node 20+ built-in fetch. Falls back to console + Admin Live OTP Log in dev mode.
 */
const PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN || 'http://127.0.0.1:3000';

const getMailFrom = () => process.env.MAIL_FROM || 'MZTRADER <security@mail.mztrader.cc.cd>';

function getProvider() {
  if ((process.env.RESEND_API_KEY || '').trim()) return 'resend';
  if ((process.env.BREVO_API_KEY || '').trim()) return 'brevo';
  if ((process.env.MAILJET_API_KEY || '').trim() && (process.env.MAILJET_SECRET_KEY || '').trim()) return 'mailjet';
  return null;
}

function parseMailbox(raw) {
  const str = String(raw || '').trim();
  const match = str.match(/^(.*?)\s*<([^<>]+)>$/);
  if (match) {
    return {
      name: match[1].replace(/^["']|["']$/g, '').trim() || 'MZTRADER',
      email: match[2].trim(),
    };
  }
  return { name: 'MZTRADER', email: str };
}

const escapeHtml = (str) => String(str ?? '')
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

async function sendEmail({ to, subject, text, html }) {
  const provider = getProvider();
  const mailFrom = getMailFrom();

  if (!provider) {
    console.log(`\n[MZTRADER MAILER - DEV/FREE MODE] To: ${to} | Subject: ${subject}\n${text}\n`);
    return { deliveredVia: 'console-and-admin-log' };
  }

  let res;
  if (provider === 'resend') {
    res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY.trim()}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ from: mailFrom, to: [to], subject, text, html }),
    });
  } else if (provider === 'brevo') {
    const sender = parseMailbox(mailFrom);
    res = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': process.env.BREVO_API_KEY.trim(),
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        sender,
        to: [{ email: to }],
        subject,
        textContent: text,
        htmlContent: html,
      }),
    });
  } else if (provider === 'mailjet') {
    const sender = parseMailbox(mailFrom);
    const creds = Buffer.from(
      `${process.env.MAILJET_API_KEY.trim()}:${process.env.MAILJET_SECRET_KEY.trim()}`
    ).toString('base64');
    res = await fetch('https://api.mailjet.com/v3.1/send', {
      method: 'POST',
      headers: {
        Authorization: `Basic ${creds}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        Messages: [{
          From: { Email: sender.email, Name: sender.name },
          To: [{ Email: to }],
          Subject: subject,
          TextPart: text,
          HTMLPart: html,
        }],
      }),
    });
  }

  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    console.error(`${provider} API error (${res.status}): ${detail}`);
    const err = new Error('تعذر إرسال رسالة التحقق عبر البريد الإلكتروني حالياً.');
    err.code = 'MAILER_DELIVERY_FAILED';
    err.status = res.status;
    err.provider = provider;
    throw err;
  }

  return { deliveredVia: provider };
}

module.exports = {
  isConfigured: () => Boolean(getProvider()),
  getProvider,

  async sendDeviceCode(to, code, { deviceLabel, ip }) {
    const safeLabel = escapeHtml(deviceLabel);
    const safeIp = escapeHtml(ip);
    return sendEmail({
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
    return sendEmail({
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
    return sendEmail({
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

  async sendDeviceChangeDecision(to, { approved, note }) {
    const loginUrl = PUBLIC_ORIGIN;
    const safeNote = note ? escapeHtml(note) : '';
    const subject = approved
      ? 'MZTRADER: تمت الموافقة على طلب تغيير الجهاز'
      : 'MZTRADER: تحديث بخصوص طلب تغيير الجهاز';
    const text = approved
      ? `تمت الموافقة من الإدارة على طلبك لاستبدال جهاز واحد. يمكنك الآن تسجيل الدخول عبر ${loginUrl} لإتمام التحقق عبر البريد الإلكتروني واستبدال جهازك القديم.${note ? `\nملاحظة الإدارة: ${note}` : ''}`
      : `تعذرت الموافقة على طلب تغيير الجهاز حالياً.${note ? `\nالسبب/الملاحظة: ${note}` : ''}`;
    return sendEmail({
      to,
      subject,
      text,
      html: `
        <div dir="rtl" style="font-family:sans-serif;line-height:1.6;">
          <h2>MZTRADER</h2>
          <p>${approved
            ? 'تمت <strong>الموافقة</strong> من الإدارة على طلبك لاستبدال جهاز مسجل (مرة واحدة). يمكنك الآن تسجيل الدخول من جهازك الجديد وإدخال كود التحقق المرسل لبريدك الإلكتروني لاختيار الجهاز المراد استبداله.'
            : 'تعذرت الموافقة على طلب تغيير الجهاز في الوقت الحالي.'}</p>
          ${safeNote ? `<p><strong>ملاحظة الإدارة:</strong> ${safeNote}</p>` : ''}
          <p><a href="${escapeHtml(loginUrl)}">${escapeHtml(loginUrl)}</a></p>
        </div>
      `,
    });
  },
};
