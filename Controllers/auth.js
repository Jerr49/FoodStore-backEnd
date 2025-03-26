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
const TokenBlacklist = require("../Models/TokenBlackList");

// Initialize Redis client
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

// Initialize Bull queue
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

// In-memory cache
const cache = new NodeCache({ stdTTL: 3600 });

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later",
});

const sensitiveActionLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: "Too many sensitive actions, please try again later",
});

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "15m";
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || "7d";

// Token generation
const generateAccessToken = (user, sessionId) => {
  return jwt.sign(
    {
      userId: user._id,
      role: user.role,
      sessionVersion: user.sessionVersion,
      sessionId,
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
};

const generateAndSaveVerificationToken = async (user) => {
  const emailVerificationToken = uuidv4();
  const emailVerificationTokenExpires = Date.now() + 24 * 60 * 60 * 1000;

  user.emailVerificationToken = emailVerificationToken;
  user.emailVerificationTokenExpires = emailVerificationTokenExpires;
  await user.save();

  return emailVerificationToken;
};

const generateRefreshToken = (user, sessionId) => {
  return jwt.sign(
    {
      userId: user._id,
      sessionVersion: user.sessionVersion,
      sessionId,
    },
    JWT_REFRESH_SECRET,
    { expiresIn: JWT_REFRESH_EXPIRES_IN }
  );
};

// Session management
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

// Cache management
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

// Register endpoint
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

// Login endpoint (with cache integration)
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const normalizedEmail = email.toLowerCase();
    let user = await User.findOne({ email: normalizedEmail }).select(
      "+password +refreshToken +sessions +isEmailVerified +sessionVersion"
    );

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Always compare password directly from database
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!user.isEmailVerified) {
      return res.status(403).json({
        message: "Please verify your email first",
        code: "EMAIL_NOT_VERIFIED",
      });
    }

    const session = user.addSession(req);
    const accessToken = generateAccessToken(user, session.id);
    const refreshToken = generateRefreshToken(user, session.id);

    user.refreshToken = refreshToken;
    await user.save();

    // Only cache non-sensitive user data
    const userForCache = {
      _id: user._id,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      sessionVersion: user.sessionVersion,
      sessions: user.sessions,
    };
    await setUserInCache(user.email, userForCache);

    res.cookie("jwt", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/api/auth/refresh-token",
    });

    res.json({
      success: true,
      accessToken,
      refreshToken,
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
    res.status(500).json({
      message: "Authentication failed",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

// Refresh token endpoint (with cache integration)
const refreshToken = async (req, res) => {
  try {
    // Get token from cookies or Authorization header
    const token = req.cookies?.jwt || req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized - No refresh token provided",
      });
    }

    // Verify token isn't blacklisted
    const isBlacklisted = await client.get(`blacklist:${token}`);
    if (isBlacklisted) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized - Token invalidated",
      });
    }

    // Verify token signature
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET, {
      algorithms: ["HS256"],
    });

    // Find user with refresh token
    const user = await User.findById(decoded.userId).select(
      "+refreshToken +sessionVersion +sessions"
    );

    if (!user || user.refreshToken !== token) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized - Invalid refresh token",
      });
    }

    // Verify session exists
    const session = user.sessions.find((s) => s.id === decoded.sessionId);
    if (!session) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized - Session not found",
      });
    }

    // Generate new tokens
    const newAccessToken = generateAccessToken(user, session.id);
    const newRefreshToken = generateRefreshToken(user, session.id);

    // Update user's refresh token
    user.refreshToken = newRefreshToken;
    await user.save();

    // Set HTTP-only cookie
    res.cookie("jwt", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: "/api/auth/refresh-token",
    });

    // Return response
    res.json({
      success: true,
      accessToken: newAccessToken,
      // Only return refreshToken if not using HTTP-only cookies
      // refreshToken: newRefreshToken,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Refresh token error:", error);

    // Clear invalid token cookie
    res.clearCookie("jwt");

    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        success: false,
        message: "Session expired - Please login again",
      });
    }

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        success: false,
        message: "Invalid token - Please login again",
      });
    }

    return res.status(500).json({
      success: false,
      message: "Internal server error",
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

// Logout endpoint
const logout = async (req, res) => {
  try {
    // 1. Token extraction (keep your existing logic)
    const tokenSources = [
      req.cookies?.jwt,
      req.headers.authorization?.split(" ")[1],
      req.body?.token,
    ];
    const token = tokenSources.find((source) => !!source);

    // 2. Cookie clearing (optimized)
    const baseCookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      path: "/",
    };

    res.clearCookie("jwt", {
      ...baseCookieOptions,
      domain: process.env.COOKIE_DOMAIN,
    });

    res.clearCookie("rt", {
      ...baseCookieOptions,
      path: "/api/auth/refresh-token",
    });

    // 3. Immediate response if no token
    if (!token) {
      return res.status(200).json({
        success: true,
        message: "Session cleared",
      });
    }

    // 4. Token processing
    let decoded;
    try {
      decoded = jwt.decode(token);

      // 5. Blacklist token (simplified)
      await TokenBlacklist.create({
        token,
        userId: decoded?.userId,
        reason: "logout",
        expiresAt: decoded?.exp
          ? new Date(decoded.exp * 1000)
          : new Date(Date.now() + 86400000),
      });

      // 6. Session cleanup (optional)
      if (decoded?.userId && decoded?.sessionId) {
        await User.updateOne(
          { _id: decoded.userId },
          { $pull: { sessions: { id: decoded.sessionId } } }
        );
      }

      return res.status(200).json({
        success: true,
        message: "Logged out successfully",
      });
    } catch (error) {
      console.error("Logout processing error:", error);
      return res.status(200).json({
        success: true,
        message: "Session cleared with partial cleanup",
      });
    }
  } catch (error) {
    console.error("Logout system error:", error);
    // Last effort to clear cookies
    res.clearCookie("jwt");
    res.clearCookie("rt");
    return res.status(500).json({
      success: false,
      message: "Logout system error",
    });
  }
};

// Logout all devices
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

// Get active sessions
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

// Terminate specific session
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

// Verify token middleware
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
  register: [authLimiter, compression(), register],
  login: [authLimiter, compression(), login],
  verifyEmail,
  logout: [compression(), logout],
  logoutAllDevices: [
    sensitiveActionLimiter,
    compression(),
    verifyToken,
    logoutAllDevices,
  ],
  getSessions: [compression(), verifyToken, getSessions],
  terminateSession: [compression(), verifyToken, terminateSession],
  verifyToken,
  refreshToken,
  checkAuth,
};
