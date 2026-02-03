import { Request, Response, NextFunction } from "express";
import { authService } from "./auth.service";
import { SignupSchema, LoginSchema, VerifyEmailSchema, TwoFactorSchema, ForgotPasswordSchema, ResetPasswordSchema, PasswordConfirmSchema } from "./auth.validators";
import { getClientIp } from "../../utils/ip";
import { setRefreshCookie, clearRefreshCookie } from "../../utils/cookies";
import { checkRateLimit } from "../../utils/rate-limit";
import { AuthRequest } from "../../middleware/auth.middleware";

// Helper to handle async errors
const catchAsync = (fn: Function) => (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

export const signup = catchAsync(async (req: Request, res: Response) => {
    const input = SignupSchema.parse(req.body);
    const result = await authService.signup(input);
    res.status(201).json({ success: true, data: result });
});

export const login = catchAsync(async (req: Request, res: Response) => {
    const ip = getClientIp(req);

    const input = LoginSchema.parse(req.body);
    const result = await authService.login(input, ip);

    if (result.refreshToken) {
        setRefreshCookie(res, result.refreshToken);
    }

    res.json({ success: true, data: result });
});

export const verifyEmail = catchAsync(async (req: Request, res: Response) => {
    const input = VerifyEmailSchema.parse(req.body);
    const result = await authService.verifyEmail(input);
    res.json({ success: true, data: result });
});

export const googleLogin = catchAsync(async (req: Request, res: Response) => {
    const { idToken } = req.body;
    if (typeof idToken !== 'string') throw { status: 400, message: "idToken required" };

    const result = await authService.googleLogin(idToken);

    if (result.refreshToken) {
        setRefreshCookie(res, result.refreshToken);
    }

    res.json({ success: true, data: result });
});

export const verify2fa = catchAsync(async (req: Request, res: Response) => {
    const { userId, code } = TwoFactorSchema.parse(req.body);
    const result = await authService.verify2FA(userId, code);

    if (result.refreshToken) {
        setRefreshCookie(res, result.refreshToken);
    }

    res.json({ success: true, data: result });
});

export const forgot = catchAsync(async (req: Request, res: Response) => {
    const input = ForgotPasswordSchema.parse(req.body);
    await authService.forgotPassword(input.email);
    res.json({ success: true, data: { message: "If email exists, reset code sent" } });
});

export const reset = catchAsync(async (req: Request, res: Response) => {
    const input = ResetPasswordSchema.parse(req.body);
    const result = await authService.resetPassword(input);
    res.json({ success: true, data: result });
});

export const logout = catchAsync(async (req: Request, res: Response) => {
    clearRefreshCookie(res);
    res.json({ success: true, data: { message: "Logged out" } });
});

export const refresh = catchAsync(async (req: Request, res: Response) => {
    const token = req.cookies.refresh_token;
    if (!token) throw { status: 401, message: "Missing refresh token" };

    const result = await authService.refresh(token);

    setRefreshCookie(res, result.refreshToken);
    res.json({ success: true, data: result });
});

export const enable2fa = catchAsync(async (req: AuthRequest, res: Response) => {
    if (!req.user) throw { status: 401, message: "Unauthorized" };
    const { password } = PasswordConfirmSchema.parse(req.body);

    const result = await authService.enable2FA(req.user.userId, password);
    res.json({ success: true, data: result });
});

export const disable2fa = catchAsync(async (req: AuthRequest, res: Response) => {
    if (!req.user) throw { status: 401, message: "Unauthorized" };
    const { password } = PasswordConfirmSchema.parse(req.body);

    const result = await authService.disable2FA(req.user.userId, password);
    res.json({ success: true, data: result });
});

export const getMe = catchAsync(async (req: AuthRequest, res: Response) => {
    if (!req.user) throw { status: 401, message: "Unauthorized" };
    const user = await authService.getMe(req.user.userId);
    res.json({ success: true, data: user });
});
