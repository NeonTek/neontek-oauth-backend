const express = require('express');
const router = express.Router();
const passport = require('passport');
const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');
const sessionController = require('../controllers/sessionController');
const profileController = require('../controllers/profileController');
const socialAuthController = require('../controllers/socialAuthController');

// public
router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.post('/login/verify-2fa', authController.verifyTwoFactor);
router.post('/refresh', authController.refresh);
router.post('/logout', authController.logout);
router.get('/verify-email', authController.verifyEmail);
router.post('/verify-email', authController.verifyEmail); 
router.post('/resend-verification', authController.resendVerification);

// -- Social Auth Routes --
// 1. Route to start the Google authentication flow
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'], session: false }));

// 2. Google callback route - Google redirects here after user grants permission
router.get(
  '/google/callback',
  passport.authenticate('google', {
    failureRedirect: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/login?error=google-auth-failed`,
    session: false,
  }),
  socialAuthController.googleCallback
);

// Magic link
router.post('/magic-login', authController.requestMagicLink);
router.get('/verify-magic-link', authController.verifyMagicLink);

// protected
router.get('/me', authMiddleware, authController.me);

router.get('/sessions', authMiddleware, sessionController.getSessions);
router.delete('/sessions/:id', authMiddleware, sessionController.revokeSession);
router.post('/sessions/revoke-all', authMiddleware, sessionController.revokeAllSessions);
router.post('/change-password', authMiddleware, authController.changePassword);
// router.post('/update-profile', authMiddleware, authController.updateProfile);
router.get('/profile', authMiddleware, profileController.getProfile);
router.put('/profile', authMiddleware, profileController.updateProfile);
router.get('/activity', authMiddleware, authController.getActivity); 

module.exports = router;
