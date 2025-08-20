
/**
 * @param {string[]} allowedRoles - An array of roles allowed to access the route (e.g., ['admin'])
 */
const checkRole = (allowedRoles) => {
  return (req, res, next) => {
    const user = req.user;

    if (!user || !user.roles || !Array.isArray(user.roles)) {
      return res.status(403).json({ message: 'Forbidden: No roles found for user.' });
    }
    
    const hasRequiredRole = user.roles.some(role => allowedRoles.includes(role));

    if (hasRequiredRole) {
      return next();
    }

    return res.status(403).json({ message: 'Forbidden: You do not have permission to access this resource.' });
  };
};

module.exports = checkRole;