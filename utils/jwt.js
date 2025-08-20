const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET must be set in env');

const ACCESS_EXPIRES = process.env.JWT_ACCESS_EXPIRES || '15m';

function signAccessToken(user) {
  const payload = {
    sub: user._id.toString(),
    email: user.email,
    roles: user.roles || []
  };

  return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_EXPIRES });
}

function verifyAccessToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

module.exports = {
  signAccessToken,
  verifyAccessToken,
};
