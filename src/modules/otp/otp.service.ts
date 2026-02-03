import crypto from "crypto";

export function generateOtpCode(): string {
    const num = crypto.randomInt(100000, 1000000);
    return num.toString();
}

export function otpExpiry(minutes: number): Date {
    return new Date(Date.now() + minutes * 60 * 1000);
}
