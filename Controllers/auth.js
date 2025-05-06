require("dotenv").config();
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");
const User = require("../Models/user");
const { sendVerificationEmail } = require("../Utils/email");
const redis = require("redis");
const Queue = require("bull");
const { body, validationResult } = require("express-validator");
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const NodeCache = require("node-cache");
const geoip = require("geoip-lite");
const device = require("device");
const TokenBlacklist = require("../Models/tokenBlacklist");

const client = redis.createClient({
  url: process.env.REDIS_URL,
  socket: {
    connectTimeout: 5000,
    reconnectStrategy: (retries) => {
      if (retries > 5) {
        return new Error("Max retries reached");
      }
      return 2000;
    },
  },
});

if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
  throw new Error("JWT secrets must be configured in environment variables");
}

client.on("error", (err) => {
  console.error("Redis error:", err);
});

client.on("connect", () => {
  console.log("Connected to Redis");
});

client.connect();

const emailQueue = new Queue("email", {
  redis: process.env.REDIS_URL || "redis://localhost:6379",
});

emailQueue.process(5, async (job) => {
  const { email, token } = job.data;
  await sendVerificationEmail(email, token);
});

emailQueue.on("error", (err) => {
  console.error("Bull queue error:", err);
});

emailQueue.on("completed", (job) => {
  console.log(`Job ${job.id} completed`);
});

const cache = new NodeCache({ stdTTL: 3600 });

const sensitiveActionLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: "Too many sensitive actions, please try again later",
});

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "15m";
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || "7d";

const generateAccessToken = (user, sessionId, customExpiresIn = null) => {
  // Calculate expiration
  const expiresIn = customExpiresIn || JWT_EXPIRES_IN;
  const expiresAt =
    Math.floor(Date.now() / 1000) +
    (typeof expiresIn === "string" ? parseJwtDuration(expiresIn) : expiresIn);

  // Create token with enhanced claims
  const token = jwt.sign(
    {
      userId: user._id,
      role: user.role,
      sessionVersion: user.sessionVersion,
      sessionId,
      iss: process.env.JWT_ISSUER || "your-app-name",
      aud: process.env.JWT_AUDIENCE || "your-app-client",
      iat: Math.floor(Date.now() / 1000),
    },
    process.env.JWT_SECRET,
    {
      expiresIn: expiresIn,
      algorithm: "HS256",
    }
  );

  return {
    token,
    expiresAt,
  };
};

const generateRefreshToken = (user, sessionId) => {
  return jwt.sign(
    {
      userId: user._id,
      sessionVersion: user.sessionVersion,
      sessionId,
      iss: process.env.JWT_ISSUER || "your-app-name",
      aud: process.env.JWT_AUDIENCE || "your-app-client",
      iat: Math.floor(Date.now() / 1000),
    },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
      algorithm: "HS256",
    }
  );
};

// Helper function to convert duration strings to seconds
function parseJwtDuration(duration) {
  const units = {
    s: 1,
    m: 60,
    h: 60 * 60,
    d: 60 * 60 * 24,
  };

  const match = duration.match(/^(\d+)([smhd])$/);
  if (!match) return 3600;

  return parseInt(match[1]) * units[match[2]];
}

const generateAndSaveVerificationToken = async (user) => {
  const emailVerificationToken = uuidv4();
  const emailVerificationTokenExpires = Date.now() + 24 * 60 * 60 * 1000;

  user.emailVerificationToken = emailVerificationToken;
  user.emailVerificationTokenExpires = emailVerificationTokenExpires;
  await user.save();

  return emailVerificationToken;
};

const createSession = (user, req) => {
  const ip =
    req.ip || req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  const geo = geoip.lookup(ip);
  const deviceInfo = device(req.headers["user-agent"]);

  const session = {
    id: uuidv4(),
    ipAddress: ip,
    location: geo ? `${geo.city}, ${geo.country}` : "Unknown",
    device: `${deviceInfo.type} (${deviceInfo.model})`,
    os: deviceInfo.os,
    browser: deviceInfo.browser,
    lastActive: new Date(),
    createdAt: new Date(),
  };

  user.sessions.push(session);
  return session;
};

const getUserFromCache = async (email) => {
  try {
    const cachedUser = cache.get(email);
    if (cachedUser) return cachedUser;

    const data = await client.get(`u:${email}`);
    if (data) {
      const user = JSON.parse(data);
      cache.set(email, user);
      return user;
    }
    return null;
  } catch (err) {
    console.error("Error fetching from cache:", err);
    return null;
  }
};

const setUserInCache = async (email, user) => {
  try {
    cache.set(email, user);
    await client.setEx(`u:${email}`, 3600, JSON.stringify(user));
  } catch (err) {
    console.error("Error saving to cache:", err);
  }
};

const clearUserFromCache = async (email) => {
  try {
    cache.del(email);
    await client.del(`u:${email}`);
  } catch (err) {
    console.error("Error clearing cache:", err);
  }
};

const register = async (req, res) => {
  const { email, password, confirmPassword, role } = req.body;

  try {
    if (password !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    const normalizedEmail = email.toLowerCase();
    const existingUser = await User.findOne({
      email: normalizedEmail,
    }).collation({ locale: "en", strength: 2 });

    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const newUser = new User({
      email: normalizedEmail,
      password,
      role: role || "user",
      isEmailVerified: false,
    });

    const emailVerificationToken = await generateAndSaveVerificationToken(
      newUser
    );
    await emailQueue.add({
      email: normalizedEmail,
      token: emailVerificationToken,
    });
    await newUser.save();

    res.status(201).json({
      message:
        "User registered successfully. Please check your email to verify your account.",
    });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
        code: "MISSING_CREDENTIALS",
        field: !email ? "email" : "password",
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // 1. First check cache for user
    const cachedUser = await getUserFromCache(normalizedEmail);
    let user;

    if (cachedUser) {
      user = cachedUser;
      // For password verification, we need fresh data from DB
      user = await User.findOne({ email: normalizedEmail }).select(
        "+password +refreshToken +sessions +isEmailVerified +sessionVersion +loginAttempts +lastLoginAttempt"
      );
    } else {
      // 2. Database fallback with full security fields
      user = await User.findOne({ email: normalizedEmail }).select(
        "+password +refreshToken +sessions +isEmailVerified +sessionVersion +loginAttempts +lastLoginAttempt"
      );

      // Cache the user if found (without sensitive password field)
      if (user) {
        await setUserInCache(normalizedEmail, {
          _id: user._id,
          email: user.email,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
          sessionVersion: user.sessionVersion,
          sessions: user.sessions,
          loginAttempts: user.loginAttempts,
          lastLoginAttempt: user.lastLoginAttempt,
        });
      }
    }

    // Security: Delay response for invalid credentials to prevent timing attacks
    await new Promise((resolve) =>
      setTimeout(resolve, 100 + Math.random() * 100)
    );

    if (!user) {
      return res.status(404).json({
        // Changed to 404 for "not found"
        success: false,
        message: "No account found with this email address",
        code: "USER_NOT_FOUND",
        field: "email",
      });
    }

    // Check if account is temporarily locked
    if (
      user.loginAttempts >= 5 &&
      Date.now() - user.lastLoginAttempt < 15 * 60 * 1000
    ) {
      return res.status(429).json({
        success: false,
        message:
          "Account temporarily locked due to too many failed attempts. Please try again in 15 minutes.",
        code: "ACCOUNT_LOCKED",
        retryAfter: Math.ceil(
          (15 * 60 * 1000 - (Date.now() - user.lastLoginAttempt)) / 1000
        ),
        field: "password",
      });
    }

    const isPasswordValid = await user.comparePassword(password);

    if (!isPasswordValid) {
      // Update failed attempt counter
      user.loginAttempts += 1;
      user.lastLoginAttempt = new Date();
      await user.save();

      // Update cache with new attempt count
      await setUserInCache(normalizedEmail, {
        _id: user._id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        sessionVersion: user.sessionVersion,
        sessions: user.sessions,
        loginAttempts: user.loginAttempts,
        lastLoginAttempt: user.lastLoginAttempt,
      });

      const attemptsLeft = 5 - user.loginAttempts;
      const warning =
        attemptsLeft > 0
          ? ` ${attemptsLeft} attempt${
              attemptsLeft !== 1 ? "s" : ""
            } remaining.`
          : " Account will be temporarily locked.";

      return res.status(401).json({
        success: false,
        message: "Incorrect password." + warning,
        code: "INCORRECT_PASSWORD",
        field: "password",
        attemptsLeft,
      });
    }

    // Reset login attempts on successful login
    user.loginAttempts = 0;
    user.lastLoginAttempt = new Date();

    if (!user.isEmailVerified) {
      return res.status(403).json({
        success: false,
        message: "Please verify your email address before logging in",
        code: "EMAIL_NOT_VERIFIED",
        field: "email",
      });
    }

    // Create detailed session
    const session = createSession(user, req);
    user.sessions.push(session);

    const { token: accessToken, expiresAt } = generateAccessToken(
      user,
      session.id
    );
    const refreshToken = generateRefreshToken(user, session.id);

    // Update user with new refresh token and save
    user.refreshToken = refreshToken;
    await user.save();

    // Update cache with fresh user data
    await setUserInCache(user.email, {
      _id: user._id,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      sessionVersion: user.sessionVersion,
      sessions: user.sessions,
      loginAttempts: user.loginAttempts,
      lastLoginAttempt: user.lastLoginAttempt,
    });

    // Set HTTP-only cookies
    res.cookie("jwt", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: process.env.JWT_ACCESS_EXPIRATION * 1000 || 15 * 60 * 1000,
      path: "/",
    });

    res.cookie("rt", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge:
        process.env.JWT_REFRESH_EXPIRATION * 1000 || 7 * 24 * 60 * 60 * 1000,
      path: "/api/auth/refresh-token",
    });

    // Successful login response
    return res.json({
      success: true,
      message: "Login successful",
      accessToken,
      refreshToken,
      expiresAt,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        currentSessionId: session.id,
      },
    });
  } catch (error) {
    console.error("Login error:", error);

    // More specific error handling
    if (error.name === "MongoError") {
      return res.status(503).json({
        success: false,
        message:
          "Our database service is temporarily unavailable. Please try again later.",
        code: "DATABASE_UOWN",
      });
    }

    return res.status(500).json({
      success: false,
      message: "An unexpected error occurred during login",
      code: "INTERNAL_SERVER_ERROR",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

const refreshToken = async (req, res) => {
  try {
    // 1. Token extraction with multiple fallbacks
    const token =
      req.cookies?.rt ||
      req.cookies?.jwt ||
      req.body?.refreshToken ||
      req.headers.authorization?.split(" ")[1];

    // Extract isExtendingSession flag from request
    const { isExtendingSession = false } = req.body;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized - No refresh token provided",
      });
    }

    // 2. Enhanced blacklist check
    const [isBlacklistedRedis, isBlacklistedMongo] = await Promise.all([
      client.get(`blacklist:${token}`),
      TokenBlacklist.findOne({ token }).lean(),
    ]);

    if (isBlacklistedRedis || isBlacklistedMongo) {
      res.clearCookie("jwt", { path: "/" });
      res.clearCookie("rt", { path: "/api/auth/refresh-token" });
      return res.status(401).json({
        success: false,
        message: "Unauthorized - Token invalidated",
      });
    }

    // 3. Token verification with additional checks
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET, {
      algorithms: ["HS256"],
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
    });

    // 4. User verification with session validation
    const user = await User.findById(decoded.userId)
      .select("+refreshToken +sessionVersion +sessions +isActive +lastActive")
      .lean();

    if (!user || user.refreshToken !== token || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized - Invalid user or token",
      });
    }

    // 5. Session validation
    const session = user.sessions.find((s) => s.id === decoded.sessionId);
    if (
      !session?.active ||
      session.ip !== req.ip ||
      session.userAgent !== req.get("User-Agent")
    ) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized - Session validation failed",
      });
    }

    // 6. Calculate expiration based on activity
    const baseExpiration =
      Math.floor(Date.now() / 1000) +
      parseInt(process.env.JWT_ACCESS_EXPIRATION);
    const expiresAt = isExtendingSession
      ? baseExpiration
      : user.lastActive &&
        Date.now() - new Date(user.lastActive).getTime() < 5 * 60 * 1000
      ? decoded.exp
      : baseExpiration;

    // 7. Token generation with updated security
    const newAccessToken = generateAccessToken(user, session.id, expiresAt);
    const newRefreshToken = generateRefreshToken(user, session.id);

    // 8. Atomic update of user session
    await User.updateOne(
      { _id: user._id, "sessions.id": session.id },
      {
        $set: {
          refreshToken: newRefreshToken,
          lastActive: new Date(),
          "sessions.$.lastUsed": new Date(),
          "sessions.$.ip": req.ip,
          "sessions.$.userAgent": req.get("User-Agent"),
        },
      }
    );

    // 9. Secure cookie settings
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      path: "/",
    };

    res.cookie("jwt", newAccessToken, {
      ...cookieOptions,
      maxAge: process.env.JWT_ACCESS_EXPIRATION * 1000,
    });

    res.cookie("rt", newRefreshToken, {
      ...cookieOptions,
      maxAge: process.env.JWT_REFRESH_EXPIRATION * 1000,
      path: "/api/auth/refresh-token",
    });

    // 10. Response with security headers
    return res
      .header(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains; preload"
      )
      .header("X-Content-Type-Options", "nosniff")
      .json({
        success: true,
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresAt,
        user: {
          id: user._id,
          email: user.email,
          role: user.role,
        },
      });
  } catch (error) {
    // Enhanced error handling
    res.clearCookie("jwt", { path: "/" });
    res.clearCookie("rt", { path: "/api/auth/refresh-token" });

    const errorResponse = {
      success: false,
      message: "Authentication failed",
    };

    if (error instanceof jwt.TokenExpiredError) {
      errorResponse.message = "Session expired - Please login again";
      return res.status(401).json(errorResponse);
    }

    if (error instanceof jwt.JsonWebTokenError) {
      errorResponse.message = "Invalid token - Please login again";
      return res.status(401).json(errorResponse);
    }

    console.error("Refresh token error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

const pingActivity = async (req, res) => {
  try {
    // Update lastActive timestamp
    await User.findByIdAndUpdate(
      req.user.id,
      { lastActive: new Date() },
      { new: true }
    );

    res.status(200).json({
      success: true,
      message: "Activity ping recorded",
    });
  } catch (error) {
    console.error("Activity ping error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to record activity",
    });
  }
};

const verifyEmail = async (req, res) => {
  const startTime = Date.now();
  try {
    const token = req.body.token || req.query.token;

    if (!token) {
      console.warn("Token missing in request");
      return res.status(400).json({
        code: "MISSING_TOKEN",
        message: "Verification token is required",
      });
    }

    let decodedToken;
    try {
      decodedToken = decodeURIComponent(token);
    } catch (err) {
      console.warn("Token decoding failed", { token });
      return res.status(400).json({
        code: "INVALID_TOKEN_FORMAT",
        message: "Malformed verification token",
      });
    }

    const user = await User.findOneAndUpdate(
      {
        emailVerificationToken: decodedToken,
        emailVerificationTokenExpires: { $gt: new Date() },
      },
      {
        $set: { isEmailVerified: true },
        $unset: {
          emailVerificationToken: "",
          emailVerificationTokenExpires: "",
        },
      },
      { new: true, maxTimeMS: 3000 }
    );

    if (!user) {
      console.warn("Invalid token attempt", {
        token: decodedToken,
        executionTime: `${Date.now() - startTime}ms`,
      });
      return res.status(400).json({
        code: "INVALID_TOKEN",
        message: "This verification link is invalid or has expired",
      });
    }

    await setUserInCache(user.email, user);

    return res.status(200).json({
      success: true,
      message: "Email verified successfully",
    });
  } catch (error) {
    console.error("Verification failed", {
      error: error.message,
      stack: error.stack,
      executionTime: `${Date.now() - startTime}ms`,
    });

    if (error.name === "MongooseError" && error.message.includes("timeout")) {
      return res.status(504).json({
        code: "DATABASE_TIMEOUT",
        message: "Verification service unavailable",
      });
    }

    return res.status(500).json({
      code: "SERVER_ERROR",
      message: "Internal server error during verification",
    });
  }
};

const logout = async (req, res) => {
  try {
    // Get token from any possible source
    const token =
      req.headers.authorization?.split(" ")[1] ||
      req.cookies?.jwt ||
      req.body?.token;

    // Clear cookies
    res.clearCookie("jwt", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      path: "/",
    });

    res.clearCookie("rt", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      path: "/api/auth/refresh-token",
    });

    // Blacklist the token if it exists and is valid
    if (token && token !== "null" && token !== "undefined") {
      try {
        const decoded = jwt.decode(token);

        // Check if token is already blacklisted
        const existingToken = await TokenBlacklist.findOne({ token });

        if (!existingToken) {
          await TokenBlacklist.create({
            token,
            userId: decoded?.userId,
            expiresAt: decoded?.exp
              ? new Date(decoded.exp * 1000)
              : new Date(Date.now() + 86400000), // Default 24h if no expiration
          });
        } else {
          console.log("Token already blacklisted");
        }
      } catch (blacklistError) {
        console.error("Blacklist error:", blacklistError);
        // Consider whether to continue or return error
      }
    }

    return res.status(200).json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (error) {
    console.error("Logout error:", error);
    // Final cleanup attempt
    res.clearCookie("jwt");
    res.clearCookie("rt");
    return res.status(200).json({
      success: true,
      message: "Session cleared",
    });
  }
};

const logoutAllDevices = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.sessionVersion += 1;
    user.refreshToken = undefined;
    user.sessions = [];
    await user.save();
    await clearUserFromCache(user.email);

    await client.set(`invalidate:${user._id}`, user.sessionVersion, {
      EX: 7 * 24 * 60 * 60,
    });

    res.clearCookie("jwt");
    res.status(200).json({ message: "Logged out from all devices" });
  } catch (error) {
    console.error("Logout all error:", error);
    res.status(500).json({ message: "Failed to logout all devices" });
  }
};

const getSessions = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("sessions");
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json(
      user.sessions.map((session) => ({
        id: session.id,
        ipAddress: session.ipAddress,
        location: session.location,
        device: session.device,
        os: session.os,
        browser: session.browser,
        lastActive: session.lastActive,
        createdAt: session.createdAt,
        current: session.id === req.user.sessionId,
      }))
    );
  } catch (error) {
    console.error("Get sessions error:", error);
    res.status(500).json({ message: "Failed to get sessions" });
  }
};

const terminateSession = async (req, res) => {
  try {
    const { sessionId } = req.params;
    const user = await User.findById(req.user.userId);

    if (!user) return res.status(404).json({ message: "User not found" });
    if (sessionId === req.user.sessionId) {
      return res
        .status(400)
        .json({ message: "Cannot terminate current session" });
    }

    user.sessions = user.sessions.filter((s) => s.id !== sessionId);
    await user.save();
    await setUserInCache(user.email, user);

    res.json({ message: "Session terminated successfully" });
  } catch (error) {
    console.error("Terminate session error:", error);
    res.status(500).json({ message: "Failed to terminate session" });
  }
};

const verifyToken = async (req, res, next) => {
  try {
    const token = req.cookies?.jwt || req.headers.authorization?.split(" ")[1];
    if (!token)
      return res.status(401).json({ message: "Authentication required" });

    const isBlacklisted = await client.get(`blacklist:${token}`);
    if (isBlacklisted)
      return res.status(401).json({ message: "Token invalidated" });

    const decoded = jwt.verify(token, JWT_REFRESH_SECRET);

    // Cache-first user lookup for session validation
    const user = await User.findById(decoded.userId).select(
      "sessionVersion email"
    );
    if (!user) return res.status(401).json({ message: "User not found" });

    const invalidateVersion = await client.get(`invalidate:${decoded.userId}`);
    if (
      invalidateVersion &&
      decoded.sessionVersion < parseInt(invalidateVersion)
    ) {
      await clearUserFromCache(user.email);
      return res.status(401).json({ message: "Session invalidated" });
    }

    req.user = decoded;
    next();
  } catch (error) {
    console.error("Token verification error:", error);
    res.status(401).json({ message: "Invalid or expired token" });
  }
};

const checkAuth = async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1] || req.cookies?.jwt;

    if (!token) {
      return res.status(200).json({ isAuthenticated: false });
    }

    // Verify token signature
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check blacklist
    const isBlacklisted = await TokenBlacklist.findOne({ token });
    if (isBlacklisted) {
      return res.status(200).json({ isAuthenticated: false });
    }

    res.status(200).json({
      isAuthenticated: true,
      user: {
        id: decoded.userId,
        role: decoded.role,
      },
      expiresAt: new Date(decoded.exp * 1000),
    });
  } catch (error) {
    res.status(200).json({ isAuthenticated: false });
  }
};

module.exports = {
  register: [compression(), register],
  login: [compression(), login],
  verifyEmail,
  logout: [compression(), logout],
  logoutAllDevices: [
    sensitiveActionLimiter,
    compression(),
    verifyToken,
    logoutAllDevices,
  ],
  getSessions: [compression(), verifyToken, getSessions],
  createSession: [compression(), verifyToken, createSession],
  getUserFromCache: [compression(), verifyToken, getUserFromCache],
  terminateSession: [compression(), verifyToken, terminateSession],
  verifyToken,
  refreshToken,
  checkAuth,
  pingActivity,
};
