
/**
 * @param {string[]} requiredScopes - An array of scopes required to access the route (e.g., ['profile:read'])
 */
const checkScope = (requiredScopes) => {
  return (req, res, next) => {
    const payload = req.user;
    
    const grantedScopes = payload.scope ? payload.scope.split(' ') : [];

    const hasRequiredScopes = requiredScopes.every(scope => grantedScopes.includes(scope));

    if (hasRequiredScopes) {
      return next();
    }

    return res.status(403).json({ 
        error: 'insufficient_scope',
        error_description: `This request requires the following scope(s): ${requiredScopes.join(', ')}`
    });
  };
};

module.exports = checkScope;