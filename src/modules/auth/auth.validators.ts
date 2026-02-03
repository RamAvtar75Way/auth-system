import { z } from "zod";

export const EmailSchema = z.string().email().max(254);

export const PasswordSchema = z
    .string()
    .min(8)
    .max(128)
    .regex(/[A-Z]/, "Must include uppercase")
    .regex(/[a-z]/, "Must include lowercase")
    .regex(/[0-9]/, "Must include number");

export const SignupSchema = z.object({
    email: EmailSchema,
    password: PasswordSchema,
});

export const LoginSchema = z.object({
    email: EmailSchema,
    password: z.string().min(1),
});

export const VerifyEmailSchema = z.object({
    email: EmailSchema,
    code: z.string().length(6),
});

export const TwoFactorSchema = z.object({
    userId: z.string(),
    code: z.string().length(6),
});

export const ForgotPasswordSchema = z.object({
    email: EmailSchema,
});

export const ResetPasswordSchema = z.object({
    token: z.string().min(20),
    password: PasswordSchema,
});

export const PasswordConfirmSchema = z.object({
    password: z.string().min(1),
})

export type SignupInput = z.infer<typeof SignupSchema>;
export type LoginInput = z.infer<typeof LoginSchema>;
export type VerifyEmailInput = z.infer<typeof VerifyEmailSchema>;
export type TwoFactorInput = z.infer<typeof TwoFactorSchema>;
export type ForgotPasswordInput = z.infer<typeof ForgotPasswordSchema>;
export type ResetPasswordInput = z.infer<typeof ResetPasswordSchema>;
export type PasswordConfirmInput = z.infer<typeof PasswordConfirmSchema>;
