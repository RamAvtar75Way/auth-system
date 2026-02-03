type Bucket = {
    count: number;
    resetAt: number;
};

const store = new Map<string, Bucket>();

export interface RateLimitOptions {
    windowMs: number;
    max: number;
}

export interface RateLimitResult {
    allowed: boolean;
    remaining: number;
    resetAt: number;
}

export function checkRateLimit(
    key: string,
    options: RateLimitOptions
): RateLimitResult {
    const now = Date.now();
    const bucket = store.get(key);

    if (!bucket || now > bucket.resetAt) {
        const newBucket: Bucket = {
            count: 1,
            resetAt: now + options.windowMs,
        };

        store.set(key, newBucket);

        return {
            allowed: true,
            remaining: options.max - 1,
            resetAt: newBucket.resetAt,
        };
    }

    if (bucket.count >= options.max) {
        return {
            allowed: false,
            remaining: 0,
            resetAt: bucket.resetAt,
        };
    }

    bucket.count += 1;

    return {
        allowed: true,
        remaining: options.max - bucket.count,
        resetAt: bucket.resetAt,
    };
}
