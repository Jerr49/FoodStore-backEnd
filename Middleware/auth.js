const jwt = require("jsonwebtoken");
const TokenBlacklist = require("../Models/TokenBlacklist"); 

exports.verifyToken = async (req, res, next) => {
  // Skip auth for specific routes
  const publicRoutes = [
    { method: 'POST', path: '/api/v1/auth/logout' },
    { method: 'POST', path: '/api/v1/auth/refresh-token' },
    { method: 'GET', path: '/api/v1/menu' },
    { method: 'GET', path: '/api/v1/categories' }
  ];

  const isPublicRoute = publicRoutes.some(route => 
    req.method === route.method && req.path === route.path
  );

  if (isPublicRoute) {
    return next();
  }

  try {
    // Get token from multiple possible sources
    const token = req.cookies?.token || 
                 req.headers.authorization?.split(' ')[1] || 
                 req.headers['x-access-token'];

    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: "Authorization token required",
        code: "MISSING_TOKEN"
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check token against blacklist
    if (await TokenBlacklist.exists({ token })) {
      return res.status(401).json({
        success: false,
        message: "Session expired. Please login again",
        code: "TOKEN_REVOKED"
      });
    }

    // Attach user to request
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    
    let message = "Invalid authorization token";
    let code = "INVALID_TOKEN";

    if (error.name === 'TokenExpiredError') {
      message = "Session expired. Please login again";
      code = "TOKEN_EXPIRED";
    } else if (error.name === 'JsonWebTokenError') {
      message = "Malformed token";
      code = "MALFORMED_TOKEN";
    }

    return res.status(401).json({ 
      success: false,
      message,
      code 
    });
  }
};

exports.verifyAdmin = (req, res, next) => {
  try {
    // Ensure verifyToken ran first
    if (!req.user) {
      throw new Error("Authentication required");
    }

    // Check admin status
    if (req.user.role !== "admin") {
      throw new Error("Insufficient privileges");
    }

    next();
  } catch (error) {
    console.error('Admin verification error:', error.message);
    res.status(403).json({ 
      success: false,
      message: error.message,
      code: "FORBIDDEN"
    });
  }
};