const crypto = require('crypto');

// Generate a random 64-byte secret
const secret = crypto.randomBytes(64).toString('hex');
console.log(secret);