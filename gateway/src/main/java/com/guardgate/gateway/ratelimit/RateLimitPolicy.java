package com.guardgate.gateway.ratelimit;

public enum RateLimitPolicy {
    /** POST /api/auth/{login,register,refresh} theo IP: chặt nhất, chống brute-force/credential stuffing. */
    AUTH_IP("auth-ip", "rate_limit_auth_ip"),
    /** Mọi request theo IP: chống flood. */
    IP("ip", "rate_limit_ip"),
    /** Request đã xác thực theo user (sub): chống một tài khoản bị lạm dụng từ nhiều IP. */
    USER("user", "rate_limit_user");

    private final String id;
    private final String metricReason;

    RateLimitPolicy(String id, String metricReason) {
        this.id = id;
        this.metricReason = metricReason;
    }

    public String id() {
        return id;
    }

    public String metricReason() {
        return metricReason;
    }
}
