package com.guardgate.gateway.ratelimit;

/**
 * @param remaining số token còn lại; -1 khi không xác định (Redis lỗi, fail-open)
 */
public record RateLimitDecision(boolean allowed, long remaining) {
}
