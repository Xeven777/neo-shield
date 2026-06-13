import "server-only"

import { serverEnv } from "@/lib/env"

/**
 * Minimal Resend HTTP client. No SDK dependency and no secrets in the client
 * bundle. When RESEND_API_KEY is absent we fall back to logging the message in
 * non-production environments so local sign-in still works.
 */

type SendEmailInput = {
  to: string
  subject: string
  html: string
  text: string
  /** Never logged in production. Used only by the development fallback. */
  devSecret?: string
}

export class EmailDeliveryError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "EmailDeliveryError"
  }
}

export async function sendTransactionalEmail({
  to,
  subject,
  html,
  text,
  devSecret,
}: SendEmailInput): Promise<void> {
  const env = serverEnv()

  if (!env.RESEND_API_KEY) {
    if (!shouldLogDevEmail()) {
      throw new EmailDeliveryError(
        "Email delivery is not configured. Set RESEND_API_KEY."
      )
    }

    console.warn(
      [
        "[email:dev] RESEND_API_KEY is not set — email was not delivered.",
        `  to: ${to}`,
        `  subject: ${subject}`,
        devSecret ? `  secret: ${devSecret}` : undefined,
      ]
        .filter(Boolean)
        .join("\n")
    )
    return
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ from: env.EMAIL_FROM, to: [to], subject, html, text }),
    signal: AbortSignal.timeout(10_000),
  })

  if (!response.ok) {
    // Deliberately do not include the response body: it can echo the payload.
    console.error(
      `[email] Resend rejected the message (status ${response.status})`
    )
    throw new EmailDeliveryError("Could not deliver email. Try again shortly.")
  }
}

function shouldLogDevEmail() {
  return (
    process.env.NODE_ENV !== "production" ||
    process.env.AUTH_EMAIL_LOG_CODES === "1"
  )
}

/* -------------------------------------------------------------------------- */
/* Templates                                                                  */
/* -------------------------------------------------------------------------- */

const shell = (title: string, body: string) => `<!doctype html>
<html>
  <body style="margin:0;background:#0b0f14;padding:32px 16px;font-family:ui-sans-serif,system-ui,-apple-system,'Segoe UI',sans-serif">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;margin:0 auto;background:#111820;border:1px solid #1f2a35;border-radius:12px">
      <tr>
        <td style="padding:28px 28px 8px">
          <div style="font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:#7dd3fc;font-weight:600">NeoShield</div>
          <h1 style="margin:10px 0 0;font-size:20px;line-height:1.3;color:#f1f5f9">${title}</h1>
        </td>
      </tr>
      <tr><td style="padding:12px 28px 28px;color:#cbd5e1;font-size:14px;line-height:1.6">${body}</td></tr>
      <tr>
        <td style="padding:16px 28px;border-top:1px solid #1f2a35;color:#64748b;font-size:12px">
          You received this email because someone requested access to NeoShield with this address.
          If that was not you, ignore this message.
        </td>
      </tr>
    </table>
  </body>
</html>`

export function otpEmail(otp: string, expiresInMinutes: number) {
  return {
    subject: `NeoShield sign-in code: ${otp}`,
    text: `Your NeoShield sign-in code is ${otp}. It expires in ${expiresInMinutes} minutes.`,
    html: shell(
      "Your sign-in code",
      `<p style="margin:0 0 16px">Enter this code to finish signing in. It expires in ${expiresInMinutes} minutes.</p>
       <div style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:30px;font-weight:700;letter-spacing:.35em;color:#f8fafc;background:#0b0f14;border:1px solid #1f2a35;border-radius:8px;padding:16px;text-align:center">${otp}</div>
       <p style="margin:16px 0 0;color:#94a3b8">Never share this code. NeoShield will not ask you for it.</p>`
    ),
  }
}

export function magicLinkEmail(url: string) {
  return {
    subject: "Your NeoShield sign-in link",
    text: `Sign in to NeoShield: ${url}`,
    html: shell(
      "Sign in with one click",
      `<p style="margin:0 0 20px">This link signs you in and expires in 15 minutes. It can only be used once.</p>
       <a href="${url}" style="display:inline-block;background:#0ea5e9;color:#04121c;font-weight:600;text-decoration:none;padding:11px 18px;border-radius:8px">Sign in to NeoShield</a>
       <p style="margin:20px 0 0;color:#94a3b8;font-size:12px;word-break:break-all">${url}</p>`
    ),
  }
}
