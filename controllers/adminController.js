const User = require('../models/User');

/**
 * GET /api/admin/users
 * Retrieves a list of all users. Admin only.
 */
exports.getAllUsers = async (req, res, next) => {
  try {
    const users = await User.find().select('-passwordHash').lean();
    res.json({ users });
  } catch (err) {
    next(err);
  }
};