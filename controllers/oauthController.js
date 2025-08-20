const Client = require('../models/Client');
const User = require('../models/User');
const AuthorizationCode = require('../models/AuthorizationCode');
const argon2 = require('argon2');
const crypto = require('crypto');
const { signAccessToken } = require('../utils/jwt');

exports.authorize = async (req, res, next) => {
    const { response_type, client_id, redirect_uri, state } = req.query;

    if (response_type !== 'code') return res.status(400).render('error', { message: 'Unsupported response_type' });
    if (!client_id || !redirect_uri) return res.status(400).render('error', { message: 'Missing required parameters' });

    try {
        const client = await Client.findOne({ clientId: client_id });
        if (!client) return res.status(400).render('error', { message: 'Invalid client_id' });
        if (!client.redirectUris.includes(redirect_uri)) return res.status(400).render('error', { message: 'Invalid redirect_uri' });

        req.session.oauth = { client_id, redirect_uri, state };

        req.session.save(async () => {
            if (req.session.userId) {
                const user = await User.findById(req.session.userId);
                return res.render('consent', { client, user });
            }
            res.render('login', { client, error: null });
        });
    } catch (err) {
        next(err);
    }
};

exports.getLoginPage = async (req, res) => {
    try {
        const client = await Client.findOne({ clientId: req.query.client_id });
        res.render('login', { client, error: req.query.error || null });
    } catch (err) {
        res.status(500).render('error', { message: 'Server error' });
    }
};

exports.handleLogin = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        
        // Check if there's an active OAuth flow
        if (!req.session.oauth) {
            return res.status(400).render('error', { message: 'No active authorization request.' });
        }

        const user = await User.findOne({ email });
        if (!user || !user.passwordHash) {
            return res.render('login', { error: 'Invalid credentials or sign-in method.' });
        }

        const passwordIsValid = await argon2.verify(user.passwordHash, password);
        if (passwordIsValid) {
            // Store user ID in the session to mark them as logged in
            req.session.userId = user._id;

            const client = await Client.findOne({ clientId: req.session.oauth.client_id });
            return res.render('consent', { client, user });
        }

        res.render('login', { error: 'Invalid credentials or sign-in method.' });

    } catch (err) {
        next(err);
    }
};

exports.handleConsent = async (req, res, next) => {
    try {
        const { action } = req.body;
        const { userId, oauth } = req.session;

        if (!userId || !oauth) {
            return res.status(400).render('error', { message: 'Session expired or invalid.' });
        }
        
        const client = await Client.findOne({ clientId: oauth.client_id });
        if (!client) {
             return res.status(400).render('error', { message: 'Invalid Client.' });
        }
        
        const redirectUrl = new URL(oauth.redirect_uri);
        if (oauth.state) redirectUrl.searchParams.set('state', oauth.state);

        req.session.oauth = null;

        if (action === 'deny') {
            redirectUrl.searchParams.set('error', 'access_denied');
            return req.session.save(() => res.render('redirect', { redirectUrl: redirectUrl.toString() }));
        }

        if (action === 'allow') {
            const codeValue = crypto.randomBytes(32).toString('hex');
            await AuthorizationCode.create({
                code: codeValue,
                user: userId,
                client: client._id,
                redirectUri: oauth.redirect_uri,
                expiresAt: new Date(Date.now() + 10 * 60 * 1000),
            });

            redirectUrl.searchParams.set('code', codeValue);
            return req.session.save(() => res.render('redirect', { redirectUrl: redirectUrl.toString() }));
        }

        return res.status(400).render('error', { message: 'Invalid action.' });
    } catch (err) {
        next(err);
    }
};

// exports.handleTokenRequest = async (req, res, next) => {
//   try {
//     const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;

//     if (grant_type !== 'authorization_code') {
//       return res.status(400).json({ error: 'unsupported_grant_type' });
//     }

//     const client = await Client.findOne({ clientId: client_id });
//     if (!client) {
//       return res.status(401).json({ error: 'invalid_client' });
//     }

//     const secretIsValid = await argon2.verify(client.clientSecretHash, client_secret);
//     if (!secretIsValid) {
//       return res.status(401).json({ error: 'invalid_client' });
//     }

//     const authCode = await AuthorizationCode.findOne({
//       code: code,
//       client: client._id,
//       redirectUri: redirect_uri,
//       expiresAt: { $gt: new Date() }
//     }).populate('user');

//     if (!authCode) {
//       return res.status(400).json({ error: 'invalid_grant' });
//     }

//     const accessToken = signAccessToken(authCode.user);
    
//     await AuthorizationCode.deleteOne({ _id: authCode._id });

//     res.json({
//       access_token: accessToken,
//       token_type: 'Bearer',
//       expires_in: 15 * 60, // 15 minutes
//     });

//   } catch (err) {
//     next(err);
//   }
// };

/**
 * POST /oauth/token
 * The secure, server-to-server endpoint for exchanging an authorization code for an access token.
 */
exports.handleTokenRequest = async (req, res, next) => {
  try {
    const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;

    if (grant_type !== 'authorization_code') {
      return res.status(400).json({ error: 'unsupported_grant_type' });
    }
    if (!code || !redirect_uri || !client_id || !client_secret) {
        return res.status(400).json({ error: 'invalid_request' });
    }

    const client = await Client.findOne({ clientId: client_id });
    if (!client) {
      return res.status(401).json({ error: 'invalid_client' });
    }
    const secretIsValid = await argon2.verify(client.clientSecretHash, client_secret);
    if (!secretIsValid) {
      return res.status(401).json({ error: 'invalid_client' });
    }

    const authCode = await AuthorizationCode.findOne({
      code: code,
      client: client._id,
      redirectUri: redirect_uri,
      expiresAt: { $gt: new Date() }
    }).populate('user');

    if (!authCode) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code is invalid, expired, or has already been used.' });
    }

    const accessToken = signAccessToken(authCode.user);
    
    await AuthorizationCode.deleteOne({ _id: authCode._id });

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 15 * 60, // 900 seconds
    });

  } catch (err) {
    next(err);
  }
};