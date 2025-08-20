const RefreshToken = require('../models/RefreshToken');
const AuthAudit = require('../models/AuthAudit');
const mongoose = require('mongoose');

/**
 * GET /api/auth/sessions
 * Returns active sessions (refresh tokens) for the authenticated user.
 */
exports.getSessions = async (req, res, next) => {
  try {
    // req.user.sub set by authMiddleware
    const userId = req.user && req.user.sub;
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    const sessions = await RefreshToken.find({ user: userId })
      .select('_id createdAt expiresAt userAgent createdByIp revoked revokedAt replacedByTokenId')
      .sort({ createdAt: -1 })
      .lean();

    // Map sessions to a safe shape (no tokenHash)
    const mapped = sessions.map(s => ({
      id: s._id,
      createdAt: s.createdAt,
      expiresAt: s.expiresAt,
      createdByIp: s.createdByIp,
      revoked: !!s.revoked,
      revokedAt: s.revokedAt || null,
      replacedByTokenId: s.replacedByTokenId || null,
      userAgent: s.userAgent,
      isCurrent: s.tokenHash === currentTokenHash,
    }));

    res.json({ sessions: mapped });
  } catch (err) {
    next(err);
  }
};

/**
 * DELETE /api/auth/sessions/:id
 * Revoke a single session (refresh token) by its id.
 */
exports.revokeSession = async (req, res, next) => {
  try {
    const userId = req.user && req.user.sub;
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    const tokenId = req.params.id;
    if (!mongoose.Types.ObjectId.isValid(tokenId)) return res.status(400).json({ message: 'Invalid session id' });

    const tokenDoc = await RefreshToken.findById(tokenId);
    if (!tokenDoc) return res.status(404).json({ message: 'Session not found' });

    if (tokenDoc.user.toString() !== userId.toString()) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    if (tokenDoc.revoked) {
      return res.status(200).json({ message: 'Session already revoked' });
    }

    tokenDoc.revoked = true;
    tokenDoc.revokedAt = new Date();
    tokenDoc.revokedByIp = req.ip;
    await tokenDoc.save();

    // audit
    await AuthAudit.create({
      user: userId,
      action: 'revoke_session',
      ip: req.ip,
      userAgent: req.get('User-Agent') || '',
      meta: { revokedSessionId: tokenId }
    });

    res.json({ message: 'Session revoked' });
  } catch (err) {
    next(err);
  }
};

/**
 * POST /api/auth/sessions/revoke-all
 * Revoke all sessions for the current user (except optionally current session - depending on UX).
 * Here we revoke all refresh tokens for the user.
 */
exports.revokeAllSessions = async (req, res, next) => {
  try {
    const userId = req.user && req.user.sub;
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    const resu = await RefreshToken.updateMany(
      { user: userId, revoked: false },
      { $set: { revoked: true, revokedAt: new Date(), revokedByIp: req.ip } }
    );

    await AuthAudit.create({
      user: userId,
      action: 'revoke_all_sessions',
      ip: req.ip,
      userAgent: req.get('User-Agent') || '',
      meta: { count: resu.modifiedCount || 0 }
    });

    // Clear cookie for current client
    // Note: cookieOptions helper exists in authController - but we can clear cookie simply:
    res.clearCookie('refreshToken', { path: '/', httpOnly: true });

    res.json({ message: 'All sessions revoked', revoked: resu.modifiedCount || 0 });
  } catch (err) {
    next(err);
  }
};
