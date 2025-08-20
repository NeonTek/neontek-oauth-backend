const crypto = require('crypto');


function generateRefreshTokenValue() {
  // 64 bytes -> 128 hex chars
  return crypto.randomBytes(64).toString('hex');
}



function generateToken(size = 32) {
  return crypto.randomBytes(size).toString('hex'); 
}


function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = {
  generateRefreshTokenValue,
  generateToken,
  hashToken,
};
