const argon2 = require('argon2');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const { generateRefreshTokenValue, generateToken, hashToken } = require('../utils/crypto');
const { signAccessToken } = require('../utils/jwt');
const AuthAudit = require('../models/AuthAudit');
const {sendMail} = require('../utils/mailer')

const REFRESH_EXPIRES_DAYS = parseInt(process.env.REFRESH_TOKEN_EXPIRES_DAYS || '30', 10);
const COOKIE_NAME = 'refreshToken';
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined; 

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


async function createRefreshTokenForUser(userId, ip) {
  const tokenValue = generateRefreshTokenValue(); // raw token sent to client
  const tokenHash = hashToken(tokenValue);
  const expiresAt = new Date(Date.now() + REFRESH_EXPIRES_DAYS * 24 * 60 * 60 * 1000);

  const refreshToken = await RefreshToken.create({
    user: userId,
    tokenHash,
    expiresAt,
    createdByIp: ip,
  });

  return { refreshToken, tokenValue };
}

exports.signup = async (req, res, next) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(409).json({ message: 'Email already in use' });

    const passwordHash = await argon2.hash(password);

    // create user, unverified
    const user = await User.create({
      email: email.toLowerCase(),
      passwordHash,
      name: name || '',
      emailVerified: false
    });

    // create verification token
    const rawToken = generateToken(32); // 64 hex chars
    const tokenHash = hashToken(rawToken);
    const expiresHours = parseInt(process.env.EMAIL_VERIFICATION_EXPIRES_HOURS || '24', 10);
    const expiresAt = new Date(Date.now() + expiresHours * 60 * 60 * 1000);

    user.emailVerificationTokenHash = tokenHash;
    user.emailVerificationExpiresAt = expiresAt;
    await user.save();

    // send verification email (do not block signup if mail fails, but log)
    try {
      const frontend = process.env.FRONTEND_URL || 'http://localhost:3000';
      const verifyUrl = `${frontend.replace(/\/$/, '')}/verify-email?token=${rawToken}&email=${encodeURIComponent(user.email)}`;
      const subject = 'Verify your NeonTek email';
      const text = `Hi ${user.name || user.email},

Thanks for creating an account at NeonTek. Please verify your email address by visiting the link below:

${verifyUrl}

This link will expire in ${expiresHours} hours.

If you did not create an account, you can ignore this message.

— NeonTek`;
      const html = `<p>Hi ${user.name || user.email},</p>
<p>Please verify your email address by clicking the link below:</p>
<p><a href="${verifyUrl}">Verify email address</a></p>
<p>This link expires in ${expiresHours} hours.</p>
<p>If you did not create an account, ignore this message.</p>`;

      const mailInfo = await sendMail({ to: user.email, subject, text, html });
      if (mailInfo && mailInfo.messageId) {
        console.log('Sent verification email, messageId=', mailInfo.messageId);
      }
    } catch (mailErr) {
      console.error('Failed to send verification email:', mailErr);
    }

    const accessToken = signAccessToken(user);
    const { refreshToken, tokenValue } = await createRefreshTokenForUser(user._id, req.ip);
    res.cookie(COOKIE_NAME, tokenValue, cookieOptions());

    res.status(201).json({
      accessToken,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        roles: user.roles,
        emailVerified: user.emailVerified
      },
      message: 'Account created. Please check your email to verify your address.'
    });
  } catch (err) {
    next(err);
  }
};


exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

    const user = await User.findOne({ email: email.toLowerCase() });
  //   if (!user.emailVerified) {
  // return res.status(403).json({ message: 'Email not verified. Please check your email for verification link.' });
  // }

    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = await argon2.verify(user.passwordHash, password);
    if (!ok) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // record login time
    user.lastLoginAt = new Date();
    await user.save();

    const accessToken = signAccessToken(user);
    const { refreshToken, tokenValue } = await createRefreshTokenForUser(user._id, req.ip);

    // set cookie
    res.cookie(COOKIE_NAME, tokenValue, cookieOptions());

    res.json({
      accessToken,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        roles: user.roles,
      }
    });
  } catch (err) {
    next(err);
  }
};

/**
 * POST /magic-login
 * Generate and send a magic login link to the user's email.
 */
exports.requestMagicLink = async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: 'Email is required.' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      console.log(`Magic link requested for non-existent user: ${email}`);
      return res.status(200).json({ message: 'If an account with that email exists, a magic link has been sent.' });
    }

    // Generate a secure, single-use token
    const rawToken = generateToken(32);
    const tokenHash = hashToken(rawToken);

    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    user.magicLinkTokenHash = tokenHash;
    user.magicLinkExpiresAt = expiresAt;
    await user.save();

    // Send the email
    const magicLink = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/api/auth/verify-magic-link?token=${rawToken}`;
    const subject = 'Your Magic Login Link for NeonTek';
    const text = `Hello ${user.name || ''},\n\nClick this link to log in to your NeonTek account:\n\n${magicLink}\n\nThis link will expire in 15 minutes.\n\nIf you did not request this, please ignore this email.`;
    const html = `<p>Hello ${user.name || ''},</p><p>Click the link below to securely log in to your NeonTek account:</p><p><a href="${magicLink}">Log in to NeonTek</a></p><p>This link is valid for 15 minutes. If you did not request this, you can safely ignore this email.</p>`;

    try {
      await sendMail({ to: user.email, subject, text, html });
    } catch (mailErr) {
      console.error('Failed to send magic link email:', mailErr);
    }
    
    res.status(200).json({ message: 'If an account with that email exists, a magic link has been sent.' });

  } catch (err) {
    next(err);
  }
};

/**
 * GET /verify-magic-link
 * Verify the token from the magic link and log the user in.
 */
exports.verifyMagicLink = async (req, res, next) => {
  try {
    const { token: rawToken } = req.query;
    if (!rawToken) {
      return res.status(400).send('Invalid or missing token.');
    }

    const tokenHash = hashToken(rawToken);

    const user = await User.findOne({
      magicLinkTokenHash: tokenHash,
      magicLinkExpiresAt: { $gt: new Date() }, 
    });

    if (!user) {
      return res.status(400).send('Login link is invalid or has expired. Please request a new one.');
    }

    // --- Login Success ---
    user.magicLinkTokenHash = null;
    user.magicLinkExpiresAt = null;
    user.lastLoginAt = new Date();
    await user.save();

    const accessToken = signAccessToken(user);
    const { tokenValue } = await createRefreshTokenForUser(user._id, req.ip);

    res.cookie(COOKIE_NAME, tokenValue, cookieOptions());

    const frontendRedirectUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/auth/social-callback?accessToken=${accessToken}`;
    res.redirect(frontendRedirectUrl);

  } catch (err) {
    next(err);
  }
};

exports.refresh = async (req, res, next) => {
  try {
    const tokenValue = req.cookies[COOKIE_NAME];
    if (!tokenValue) return res.status(401).json({ message: 'No refresh token' });

    const tokenHash = hashToken(tokenValue);
    const existing = await RefreshToken.findOne({ tokenHash }).populate('user');

    // Token not found -> possible reuse or removal
    if (!existing) {
      // Security: can't determine user from token, but we should clear cookie
      res.clearCookie(COOKIE_NAME, cookieOptions());
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    // If token not active
    if (existing.revoked || existing.isExpired) {
      res.clearCookie(COOKIE_NAME, cookieOptions());
      return res.status(401).json({ message: 'Refresh token is revoked or expired' });
    }

    // Issue new tokens (rotation)
    const user = existing.user;
    existing.revoked = true;
    existing.revokedAt = new Date();
    existing.revokedByIp = req.ip;

    // Create new refresh token
    const { refreshToken: newRefreshDoc, tokenValue: newTokenValue } = await createRefreshTokenForUser(user._id, req.ip);

    // link replacement
    existing.replacedByTokenId = newRefreshDoc._id;
    await existing.save();

    // issue new access token
    const accessToken = signAccessToken(user);

    // set new cookie
    res.cookie(COOKIE_NAME, newTokenValue, cookieOptions());

    res.json({
      accessToken,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        roles: user.roles
      }
    });
  } catch (err) {
    next(err);
  }
};

exports.logout = async (req, res, next) => {
  try {
    const tokenValue = req.cookies[COOKIE_NAME];
    if (!tokenValue) {
      // ensure cookie cleared
      res.clearCookie(COOKIE_NAME, cookieOptions());
      return res.status(200).json({ message: 'Logged out' });
    }

    const tokenHash = hashToken(tokenValue);
    const existing = await RefreshToken.findOne({ tokenHash });
    if (existing) {
      existing.revoked = true;
      existing.revokedAt = new Date();
      existing.revokedByIp = req.ip;
      await existing.save();
    }

    res.clearCookie(COOKIE_NAME, cookieOptions());
    res.json({ message: 'Logged out' });
  } catch (err) {
    next(err);
  }
};

exports.me = async (req, res, next) => {
  try {
    // auth middleware sets req.user (user id + claims)
    const userId = req.user && req.user.sub;
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    const user = await User.findById(userId).select('-passwordHash');
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json({
      id: user._id,
      email: user.email,
      name: user.name,
      roles: user.roles,
      emailVerified: user.emailVerified,
      lastLoginAt: user.lastLoginAt
    });
  } catch (err) {
    next(err);
  }
};

exports.changePassword = async (req, res, next) => {
  try {
    const userId = req.user && req.user.sub;
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'currentPassword and newPassword are required' });
    }

    // basic password policy
    if (newPassword.length < 8) {
      return res.status(400).json({ message: 'New password must be at least 8 characters long' });
    }

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // verify current password
    const ok = await argon2.verify(user.passwordHash, currentPassword);
    if (!ok) return res.status(401).json({ message: 'Current password is incorrect' });

    // hash and save new password
    const newHash = await argon2.hash(newPassword);
    user.passwordHash = newHash;
    await user.save();

    // revoke refresh tokens
    const revokeRes = await RefreshToken.updateMany(
      { user: userId, revoked: false },
      { $set: { revoked: true, revokedAt: new Date(), revokedByIp: req.ip } }
    );

    // clear cookie for current client
    res.clearCookie('refreshToken', { path: '/', httpOnly: true });

    // audit
    await AuthAudit.create({
      user: userId,
      action: 'change_password',
      ip: req.ip,
      userAgent: req.get('User-Agent') || '',
      meta: { revokedCount: revokeRes.modifiedCount || revokeRes.nModified || 0 }
    });

    try {
      const subject = "Your NeonTek password was changed";
      const text = `Hi ${user.name || user.email},

This is a confirmation that the password for your NeonTek account (${user.email}) was recently changed.

If you changed your password, no action is needed.

If you did NOT change your password, immediately reset it here:
https://accounts.neontek.co.ke/forgot-password

IP: ${req.ip}
Time: ${new Date().toISOString()}

Regards,
NeonTek Security Team
`;
      const html = `<p>Hi ${user.name || user.email},</p>
<p>This is a confirmation that the password for your NeonTek account (<strong>${user.email}</strong>) was recently changed.</p>
<p><strong>If you changed your password</strong>, no action is needed.</p>
<p><strong>If you did <em>not</em> change your password</strong>, immediately reset it by visiting <a href="https://accounts.neontek.co.ke/forgot-password">this link</a>.</p>
<ul>
<li>IP: ${req.ip}</li>
<li>Time: ${new Date().toLocaleString()}</li>
</ul>
<p>Regards,<br/>NeonTek Security Team</p>`;

      const mailRes = await sendMail({
        to: user.email,
        subject,
        text,
        html,
      });

     
      if (mailRes.previewUrl) {
        console.log('Password change email preview URL:', mailRes.previewUrl);
      }
    } catch (mailErr) {
      console.error('Failed to send change-password email:', mailErr);
    }

    return res.json({ message: 'Password changed — all sessions revoked. Please log in again.' });
  } catch (err) {
    next(err);
  }
};


exports.updateProfile = async (req, res, next) => {
  try {
    const userId = req.user && req.user.sub;
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    const { name, avatarUrl } = req.body;

    // Basic validation
    const updates = {};
    if (typeof name !== 'undefined') {
      if (typeof name !== 'string' || name.trim().length === 0 || name.length > 100) {
        return res.status(400).json({ message: 'Name must be a non-empty string (max 100 chars)' });
      }
      updates.name = name.trim();
    }

    if (typeof avatarUrl !== 'undefined') {
      if (typeof avatarUrl !== 'string' || avatarUrl.length > 1000) {
        return res.status(400).json({ message: 'avatarUrl must be a string (max 1000 chars)' });
      }
      const maybeUrl = avatarUrl.trim();
      if (maybeUrl && !/^https?:\/\//i.test(maybeUrl)) {
        return res.status(400).json({ message: 'avatarUrl must be an absolute URL starting with http(s)://' });
      }
      updates.avatarUrl = maybeUrl;
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ message: 'No valid fields to update' });
    }

    const user = await User.findByIdAndUpdate(userId, { $set: updates }, { new: true }).select('-passwordHash');

    if (!user) return res.status(404).json({ message: 'User not found' });

    // Audit log
    await AuthAudit.create({
      user: userId,
      action: 'update_profile',
      ip: req.ip,
      userAgent: req.get('User-Agent') || '',
      meta: { updatedFields: Object.keys(updates) }
    });

    // Return updated public profile
    res.json({
      id: user._id,
      email: user.email,
      name: user.name,
      avatarUrl: user.avatarUrl || null,
      roles: user.roles,
      emailVerified: user.emailVerified,
      lastLoginAt: user.lastLoginAt
    });
  } catch (err) {
    next(err);
  }
};


exports.verifyEmail = async (req, res, next) => {
  try {
    const rawToken = req.query.token || req.body.token;
    const email = req.query.email || req.body.email;

    if (!rawToken || !email) return res.status(400).json({ message: 'Token and email required' });

    const tokenHash = hashToken(String(rawToken));
    // find the user with matching token hash and email
    const user = await User.findOne({
      email: email.toLowerCase(),
      emailVerificationTokenHash: tokenHash
    });

    if (!user) return res.status(400).json({ message: 'Invalid or expired verification token' });

    if (!user.emailVerificationExpiresAt || user.emailVerificationExpiresAt < new Date()) {
      return res.status(400).json({ message: 'Verification token expired' });
    }

    // mark verified
    user.emailVerified = true;
    user.emailVerificationTokenHash = null;
    user.emailVerificationExpiresAt = null;
    await user.save();

    // audit
    await AuthAudit.create({
      user: user._id,
      action: 'email_verified',
      ip: req.ip,
      userAgent: req.get('User-Agent') || ''
    });

    const redirectUrl = (process.env.FRONTEND_URL || 'http://localhost:3000') + '/verified';
    if (req.accepts('html')) {
      return res.redirect(302, redirectUrl);
    }
    res.json({ message: 'Email verified', redirect: redirectUrl });
  } catch (err) {
    next(err);
  }
};

exports.resendVerification = async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.emailVerified) return res.status(400).json({ message: 'Email already verified' });

    const rawToken = generateToken(32);
    const tokenHash = hashToken(rawToken);
    const expiresHours = parseInt(process.env.EMAIL_VERIFICATION_EXPIRES_HOURS || '24', 10);
    const expiresAt = new Date(Date.now() + expiresHours * 60 * 60 * 1000);

    user.emailVerificationTokenHash = tokenHash;
    user.emailVerificationExpiresAt = expiresAt;
    await user.save();

    // send mail
    try {
      const frontend = process.env.FRONTEND_URL || 'http://localhost:3000';
      const verifyUrl = `${frontend.replace(/\/$/, '')}/verify-email?token=${rawToken}&email=${encodeURIComponent(user.email)}`;
      const subject = 'Verify your NeonTek email';
      const text = `Hi ${user.name || user.email}, please verify: ${verifyUrl}`;
      await sendMail({ to: user.email, subject, text, html: `<a href="${verifyUrl}">Verify email</a>` });
    } catch (mailErr) {
      console.error('Failed to send verification email (resend):', mailErr);
    }

    res.json({ message: 'Verification email sent if the address exists' });
  } catch (err) {
    next(err);
  }
};


