const rateLimit = require('express-rate-limit');

module.exports = {
  authLimiter: rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP, please try again later',
  }),

  sensitiveActionLimiter: rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: 'Too many sensitive actions, please try again later',
  })
};