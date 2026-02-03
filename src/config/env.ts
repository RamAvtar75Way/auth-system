import { z } from "zod";

const envSchema = z.object({
    MONGO_URI: z.string().url(),
    JWT_ACCESS_SECRET: z.string().min(1),
    JWT_REFRESH_SECRET: z.string().min(1),
    GOOGLE_CLIENT_ID: z.string().min(1),
    MAIL_USER: z.string().email(),
    MAIL_PASS: z.string().min(1),
    PORT: z.string().default("4000"),
});

export type Env = z.infer<typeof envSchema>;

export function getEnv(key: keyof Env): string {
    const parsed = envSchema.safeParse(process.env);

    if (!parsed.success) {
        console.error("❌ Invalid environment variables:", parsed.error.format());
        throw new Error("Invalid environment variables");
    }

    return parsed.data[key];
}
