// Inside Middleware/auth.js
const jwt = require("jsonwebtoken");

exports.verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies?.jwt;
    
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    // Verify token and check expiration
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Optional: Check token against blacklist
    const isBlacklisted = await TokenBlacklist.findOne({ token });
    if (isBlacklisted) {
      return res.status(401).json({ message: "Token revoked" });
    }

    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        message: "Token expired",
        code: "TOKEN_EXPIRED" 
      });
    }
    return res.status(401).json({ message: "Invalid token" });
  }
};

// Verify Admin (must be exported)
exports.verifyAdmin = async (req, res, next) => {
  try {
    if (!req.user) throw new Error("Not authenticated");
    if (req.user.role !== "admin") throw new Error("Admin access required");
    next();
  } catch (error) {
    res.status(403).json({ message: error.message });
  }
};