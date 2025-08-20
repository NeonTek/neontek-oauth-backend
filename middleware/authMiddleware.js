const { verifyAccessToken } = require('../utils/jwt');

module.exports = function (req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Missing or invalid authorization header' });
  }
  const token = authHeader.split(' ')[1];

  console.log("--- BACKEND AUTH MIDDLEWARE ---");
  console.log("Received Token:", token);

  try {
    const payload = verifyAccessToken(token);

    console.log("Token verification successful. Payload:", payload);
    console.log("----------------------------");

    req.user = payload;
    next();
  } catch (err) {

    console.error("Token verification FAILED. Error:", err.message);
    console.log("----------------------------");
    
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};
