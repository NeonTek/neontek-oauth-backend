const { signAccessToken } = require('../utils/jwt');
const RefreshToken = require('../models/RefreshToken');
const { generateRefreshTokenValue, hashToken } = require('../utils/crypto');

const REFRESH_EXPIRES_DAYS = parseInt(process.env.REFRESH_TOKEN_EXPIRES_DAYS || '30', 10);
const COOKIE_NAME = 'refreshToken';

function cookieOptions() {
  const isProd = process.env.NODE_ENV === 'production';
  return {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    domain: isProd ? process.env.COOKIE_DOMAIN : undefined,
    path: '/',
    maxAge: REFRESH_EXPIRES_DAYS * 24 * 60 * 60 * 1000,
  };
}

async function createRefreshTokenForUser(userId, req) {
  const tokenValue = generateRefreshTokenValue();
  const tokenHash = hashToken(tokenValue);
  const expiresAt = new Date(Date.now() + REFRESH_EXPIRES_DAYS * 24 * 60 * 60 * 1000);

  const refreshToken = await RefreshToken.create({
    user: userId,
    tokenHash,
    expiresAt,
    createdByIp: req.ip,
    userAgent: req.get('User-Agent') || '',
  });

  return { refreshToken, tokenValue };
}


exports.googleCallback = async (req, res, next) => {
  try {
    const user = req.user;

    const accessToken = signAccessToken(user);
    const { tokenValue } = await createRefreshTokenForUser(user._id, req);

    // Set the refresh token as a cookie
    res.cookie(COOKIE_NAME, tokenValue, cookieOptions());

    // Record login time
    user.lastLoginAt = new Date();
    await user.save();
    
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    res.redirect(`${frontendUrl}/auth/callback?accessToken=${accessToken}`);
  } catch (err) {
    next(err);
  }
};