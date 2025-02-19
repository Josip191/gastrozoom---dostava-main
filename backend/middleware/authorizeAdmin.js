const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Pristup nije dozvoljen' });
  }
  next();
};

module.exports = authorizeAdmin;