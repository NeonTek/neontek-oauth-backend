const express = require('express');
const router = express.Router();

const oauthController = require('../controllers/oauthController');

// Entry point for the OAuth flow
router.get('/authorize', oauthController.authorize);

// Routes for the login page
router.get('/login', oauthController.getLoginPage);
router.post('/login', oauthController.handleLogin);

// Route to handle the user's consent decision
router.post('/consent', oauthController.handleConsent);
router.post('/token', oauthController.handleTokenRequest);

module.exports = router;