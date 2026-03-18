const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const privateKey = fs.readFileSync(path.join(__dirname, '../private.pem'), 'utf8');
const publicKey = fs.readFileSync(path.join(__dirname, '../public.pem'), 'utf8');

module.exports = {
    generateToken: function (payload) {
        return jwt.sign(payload, privateKey, { algorithm: 'RS256', expiresIn: '1h' });
    },
    verifyToken: function (token) {
        try {
            return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        } catch (err) {
            return null;
        }
    },
    authenticate: function (req, res, next) {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).send({ message: 'Access token required' });
        }
        const decoded = this.verifyToken(token);
        if (!decoded) {
            return res.status(401).send({ message: 'Invalid token' });
        }
        req.user = decoded;
        next();
    }
};