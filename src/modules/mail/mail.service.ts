import nodemailer, { Transporter } from "nodemailer";
import { getEnv } from "../../config/env";

let transporter: Transporter | null = null;

function getTransporter(): Transporter {
    if (transporter) return transporter;

    const user = getEnv("MAIL_USER");
    const pass = getEnv("MAIL_PASS");

    transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user,
            pass,
        },
    });

    return transporter;
}

export async function sendMail(
    to: string,
    subject: string,
    html: string
): Promise<void> {
    const tx = getTransporter();
    const from = getEnv("MAIL_USER");

    await tx.sendMail({
        from: `"Auth System" <${from}>`,
        to,
        subject,
        html,
    });
}
