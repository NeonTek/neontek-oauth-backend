const User = require('../models/User');

/**
 * Helper to pick allowed fields from body
 */
function pickAllowed(body) {
  const allowed = {};
  const fields = [
    'name',
    'givenName',
    'familyName',
    'profilePicture',
    'phoneNumber',
    'gender',
    'birthday',
    'language',
    'country',
    'timezone'
  ];

  fields.forEach((f) => {
    if (typeof body[f] !== 'undefined') allowed[f] = body[f];
  });
  return allowed;
}

function validateProfile(updates) {
  const errors = [];

  if (updates.name && updates.name.length > 200) errors.push('name too long (max 200)');
  if (updates.givenName && updates.givenName.length > 100) errors.push('givenName too long (max 100)');
  if (updates.familyName && updates.familyName.length > 100) errors.push('familyName too long (max 100)');

  if (updates.profilePicture && typeof updates.profilePicture === 'string') {
    if (updates.profilePicture.length > 2000) errors.push('profilePicture URL too long');
    if (!/^https?:\/\//i.test(updates.profilePicture)) errors.push('profilePicture must be an http(s) URL');
  }

  if (updates.phoneNumber && updates.phoneNumber.length > 40) errors.push('phoneNumber too long');

  if (updates.gender && !['male','female','other','prefer_not_to_say'].includes(updates.gender)) {
    errors.push('invalid gender');
  }

  if (updates.birthday) {
    const d = new Date(updates.birthday);
    if (Number.isNaN(d.getTime())) errors.push('invalid birthday date');
    else {
      const now = new Date();
      if (d > now) errors.push('birthday cannot be in the future');
      else updates.birthday = d;
    }
  }

  if (updates.language && updates.language.length > 10) errors.push('invalid language code');
  if (updates.country && updates.country.length > 200) errors.push('country too long');
  if (updates.timezone && updates.timezone.length > 100) errors.push('timezone too long');

  return errors;
}

/**
 * GET /api/auth/profile
 */
exports.getProfile = async (req, res, next) => {
  try {
    const userId = req.user && req.user.sub;
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    const user = await User.findById(userId).select('-passwordHash -emailVerificationTokenHash -emailVerificationExpiresAt').lean();
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json(user);
  } catch (err) {
    next(err);
  }
};

/**
 * PUT /api/auth/profile
 */
exports.updateProfile = async (req, res, next) => {
  try {
    const userId = req.user && req.user.sub;
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    const updates = pickAllowed(req.body);
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ message: 'No updatable fields provided' });
    }

    // validate
    const errors = validateProfile(updates);
    if (errors.length) return res.status(400).json({ message: 'Validation failed', errors });

    if (typeof updates.phoneNumber !== 'undefined') {
      updates.phoneVerified = false;
    }

    const user = await User.findByIdAndUpdate(userId, { $set: updates }, { new: true }).select('-passwordHash -emailVerificationTokenHash -emailVerificationExpiresAt');
    if (!user) return res.status(404).json({ message: 'User not found' });


    res.json(user);
  } catch (err) {
    next(err);
  }
};
