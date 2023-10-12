const jwt = require('jsonwebtoken');
const jwtSecret = process.env.JWT_SECRET || 'your-secret-key';

function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }

  jwt.verify(token.replace('Bearer ', ''), jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }

    // If the token is valid, store the user ID in the request for further processing
    req.userId = decoded.userId;
    next();
  });
}

module.exports = {
  verifyToken,
};
