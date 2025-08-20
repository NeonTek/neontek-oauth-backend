const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const User = require('../models/User');

exports.generateSecret = async (req, res, next) => {
  try {
    const userId = req.user.sub;
    const secret = speakeasy.generateSecret({
      name: `NeonTek (${req.user.email})`, 
    });

    await User.findByIdAndUpdate(userId, { twoFactorSecret: secret.base32 });

    // Generate a QR code for the user to scan
    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
      if (err) {
        return next(new Error('Could not generate QR code.'));
      }
      res.json({
        message: 'Scan this QR code with your authenticator app.',
        secret: secret.base32,
        qrCodeUrl: data_url,
      });
    });
  } catch (err) {
    next(err);
  }
};


/**
 * POST /api/2fa/verify
 * Verifies the user's token and permanently enables 2FA.
 */
exports.verifyAndEnable = async (req, res, next) => {
  try {
    const userId = req.user.sub;
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ message: 'Token is required.' });
    }

    const user = await User.findById(userId);
    if (!user || !user.twoFactorSecret) {
      return res.status(400).json({ message: '2FA secret not found. Please generate one first.' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: token,
    });

    if (verified) {
      user.twoFactorEnabled = true;
      await user.save();
      return res.json({ message: '2FA has been enabled successfully.' });
    }

    return res.status(400).json({ message: 'Invalid token. Please try again.' });
  } catch (err) {
    next(err);
  }
};


/**
 * POST /api/2fa/disable
 * Disables 2FA for the user's account.
 */
exports.disable = async (req, res, next) => {
  try {
    const userId = req.user.sub;
    
    // User Password

    const user = await User.findByIdAndUpdate(userId, {
      twoFactorEnabled: false,
      twoFactorSecret: null,
    });
    
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.json({ message: '2FA has been disabled.' });
  } catch (err) {
    next(err);
  }
};