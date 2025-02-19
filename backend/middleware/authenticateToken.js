const jwt = require('jsonwebtoken');
const prisma = require('../config/prisma');
const dotenv = require('dotenv');

dotenv.config();

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.status(401).json({ error: 'Nije osiguran token' });

  try {
    const revokedToken = await prisma.revokedToken.findUnique({
      where: { token },
    });

    if (revokedToken) {
      return res.status(401).json({ message: 'Token nije više važeći' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ error: 'Nevažeći token' });
      req.user = user;
      next();
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
};

module.exports = authenticateToken;