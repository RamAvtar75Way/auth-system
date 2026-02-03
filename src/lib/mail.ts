import nodemailer, { Transporter } from "nodemailer"
import { getEnv } from "@/utils/env"

let transporter: Transporter | null = null

function getTransporter(): Transporter {
  if (transporter) return transporter

  const user = getEnv("MAIL_USER")
  const pass = getEnv("MAIL_PASS")

  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user,
      pass,
    },
  })

  return transporter
}

export async function sendMail(
  to: string,
  subject: string,
  html: string
): Promise<void> {
  const tx = getTransporter()

  await tx.sendMail({
    from: `"Auth System" <${getEnv("MAIL_USER")}>`,
    to,
    subject,
    html,
  })
}
