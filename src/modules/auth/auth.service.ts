import { User } from "../user/user.model";
import { hashPassword, verifyPassword, sha256 } from "../../utils/hash";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "../token/jwt.service";
import { generateOtpCode, otpExpiry } from "../otp/otp.service";
import { sendMail } from "../mail/mail.service";
import { otpEmailTemplate } from "../mail/templates";
import { SignupInput, LoginInput, VerifyEmailInput, TwoFactorInput, ForgotPasswordInput, ResetPasswordInput, PasswordConfirmInput } from "./auth.validators";
import crypto from "crypto";
import { OAuth2Client } from "google-auth-library";
import { getEnv } from "../../config/env";

const MAX_FAILED = 5;
const LOCK_MINUTES = 15;

const googleClient = new OAuth2Client(getEnv("GOOGLE_CLIENT_ID"));

export class AuthService {
    async signup(input: SignupInput) {
        const existing = await User.findOne({ email: input.email });
        if (existing) {
            throw { status: 400, message: "User already exists" };
        }

        const passwordHash = await hashPassword(input.password);
        const otp = generateOtpCode();
        const emailVerifyCodeHash = sha256(otp);
        const emailVerifyExpiry = otpExpiry(10);

        const user = await User.create({
            email: input.email,
            passwordHash,
            emailVerifyCodeHash,
            emailVerifyExpiry,
        });

        await sendMail(
            user.email,
            "Verify your email",
            otpEmailTemplate(otp)
        );

        return { userId: user._id, email: user.email };
    }

    async login(input: LoginInput, ip: string) {
        const user = await User.findOne({ email: input.email });
        if (!user || !user.passwordHash) {
            throw { status: 401, message: "Invalid credentials" };
        }

        if (!user.isEmailVerified) {
            throw { status: 403, message: "Email not verified" };
        }

        if (user.lockUntil && user.lockUntil.getTime() > Date.now()) {
            throw { status: 423, message: "Account locked" };
        }

        const valid = await verifyPassword(input.password, user.passwordHash);
        if (!valid) {
            user.failedLoginAttempts += 1;
            if (user.failedLoginAttempts >= MAX_FAILED) {
                user.lockUntil = otpExpiry(LOCK_MINUTES);
                user.failedLoginAttempts = 0;
            }
            await user.save();
            throw { status: 401, message: "Invalid credentials" };
        }

        user.failedLoginAttempts = 0;
        user.lockUntil = undefined;

        if (user.twoFactorEnabled) {
            const otp = generateOtpCode();
            user.twoFactorCodeHash = sha256(otp);
            user.twoFactorExpiry = otpExpiry(10);
            await user.save();

            await sendMail(user.email, "Login Verification", otpEmailTemplate(otp));

            return { requiresTwoFactor: true, userId: user._id, accessToken: "" };
        }

        await user.save();

        const accessToken = signAccessToken({ userId: user._id.toString(), tokenVersion: user.tokenVersion || 0, type: "access" });
        const refreshToken = signRefreshToken({ userId: user._id.toString(), tokenVersion: user.tokenVersion || 0, type: "refresh" });

        user.refreshTokenHash = sha256(refreshToken);
        await user.save();

        return { requiresTwoFactor: false, accessToken, refreshToken };
    }

    async verifyEmail(input: VerifyEmailInput) {
        const user = await User.findOne({ email: input.email });
        if (!user || !user.emailVerifyCodeHash || !user.emailVerifyExpiry) {
            throw { status: 400, message: "Invalid request" };
        }

        if (user.emailVerifyExpiry.getTime() < Date.now()) {
            throw { status: 400, message: "Code expired" };
        }

        if (sha256(input.code) !== user.emailVerifyCodeHash) {
            throw { status: 400, message: "Invalid code" };
        }

        user.isEmailVerified = true;
        user.emailVerifyCodeHash = undefined;
        user.emailVerifyExpiry = undefined;
        await user.save();

        return { message: "Email verified" };
    }

    async googleLogin(idToken: string) {
        const ticket = await googleClient.verifyIdToken({
            idToken,
            audience: getEnv("GOOGLE_CLIENT_ID")
        });
        const payload = ticket.getPayload();
        if (!payload?.email) throw { status: 401, message: "Invalid Google Token" };

        let user = await User.findOne({ email: payload.email });
        if (!user) {
            user = await User.create({
                email: payload.email,
                googleId: payload.sub,
                isEmailVerified: true
            });
        } else if (!user.googleId) {
            user.googleId = payload.sub;
        }

        if (user.twoFactorEnabled) {
            const otp = generateOtpCode();
            user.twoFactorCodeHash = sha256(otp);
            user.twoFactorExpiry = otpExpiry(10);
            await user.save();
            await sendMail(user.email, "Login Verification", otpEmailTemplate(otp));
            return { requiresTwoFactor: true, userId: user._id, accessToken: "" };
        }

        const accessToken = signAccessToken({ userId: user._id.toString(), tokenVersion: user.tokenVersion || 0, type: "access" });
        const refreshToken = signRefreshToken({ userId: user._id.toString(), tokenVersion: user.tokenVersion || 0, type: "refresh" });

        user.refreshTokenHash = sha256(refreshToken);
        await user.save();

        return { requiresTwoFactor: false, accessToken, refreshToken };
    }

    async verify2FA(userId: string, code: string) {
        const user = await User.findById(userId);
        if (!user || !user.twoFactorCodeHash || !user.twoFactorExpiry) throw { status: 400, message: "Invalid request" };

        if (user.twoFactorExpiry.getTime() < Date.now()) throw { status: 400, message: "Code expired" };

        if (sha256(code) !== user.twoFactorCodeHash) {
            throw { status: 400, message: "Invalid code" };
        }

        user.twoFactorCodeHash = undefined;
        user.twoFactorExpiry = undefined;
        await user.save();

        const accessToken = signAccessToken({ userId: user._id.toString(), tokenVersion: user.tokenVersion || 0, type: "access" });
        const refreshToken = signRefreshToken({ userId: user._id.toString(), tokenVersion: user.tokenVersion || 0, type: "refresh" });

        user.refreshTokenHash = sha256(refreshToken);
        await user.save();

        return { accessToken, refreshToken };
    }

    async forgotPassword(email: string) {
        const user = await User.findOne({ email });
        if (!user) return;

        const token = crypto.randomBytes(32).toString("hex");
        user.resetPasswordTokenHash = sha256(token);
        user.resetPasswordExpiry = otpExpiry(60);
        await user.save();

        await sendMail(user.email, "Reset Password", `Your reset token is: ${token}`);
    }

    async resetPassword(input: ResetPasswordInput) {
        const tokenHash = sha256(input.token);
        const user = await User.findOne({ resetPasswordTokenHash: tokenHash });

        if (!user || !user.resetPasswordExpiry) {
            throw { status: 400, message: "Invalid or expired reset token" };
        }

        if (user.resetPasswordExpiry.getTime() < Date.now()) {
            throw { status: 400, message: "Reset token expired" };
        }

        user.passwordHash = await hashPassword(input.password);
        user.resetPasswordTokenHash = undefined;
        user.resetPasswordExpiry = undefined;
        user.tokenVersion = (user.tokenVersion || 0) + 1;
        user.refreshTokenHash = undefined;
        user.failedLoginAttempts = 0;
        user.lockUntil = undefined;

        await user.save();
        return { message: "Password reset successful" };
    }

    async logout(userId: string) {
        const user = await User.findById(userId);
        if (user) {
            user.refreshTokenHash = undefined;
            await user.save();
        }
    }

    async refresh(refreshToken: string) {
        let payload;
        try {
            payload = verifyRefreshToken(refreshToken);
        } catch {
            throw { status: 401, message: "Invalid token" };
        }

        if (payload.type !== "refresh") throw { status: 401, message: "Invalid token type" };

        const user = await User.findById(payload.userId);
        if (!user) throw { status: 404, message: "User not found" };

        if (user.tokenVersion !== payload.tokenVersion) throw { status: 401, message: "Token revoked" };

        const incomingHash = sha256(refreshToken);
        if (!user.refreshTokenHash || incomingHash !== user.refreshTokenHash) {
            throw { status: 401, message: "Invalid refresh token" };
        }

        const newAccessToken = signAccessToken({ userId: user._id.toString(), tokenVersion: user.tokenVersion || 0, type: "access" });
        const newRefreshToken = signRefreshToken({ userId: user._id.toString(), tokenVersion: user.tokenVersion || 0, type: "refresh" });

        user.refreshTokenHash = sha256(newRefreshToken);
        await user.save();

        return { accessToken: newAccessToken, refreshToken: newRefreshToken };
    }

    async enable2FA(userId: string, password: string) {
        const user = await User.findById(userId);
        if (!user || !user.passwordHash) throw { status: 404, message: "User not found" };

        const valid = await verifyPassword(password, user.passwordHash);
        if (!valid) throw { status: 401, message: "Invalid password" };

        user.twoFactorEnabled = true;
        await user.save();
        return { message: "2FA enabled" };
    }

    async disable2FA(userId: string, password: string) {
        const user = await User.findById(userId);
        if (!user || !user.passwordHash) throw { status: 404, message: "User not found" };

        const valid = await verifyPassword(password, user.passwordHash);
        if (!valid) throw { status: 401, message: "Invalid password" };

        user.twoFactorEnabled = false;
        await user.save();
        return { message: "2FA disabled" };
    }

    async getMe(userId: string) {
        const user = await User.findById(userId).select("-passwordHash -twoFactorCodeHash -refreshTokenHash");
        if (!user) throw { status: 404, message: "User not found" };
        return user;
    }
}

export const authService = new AuthService();
