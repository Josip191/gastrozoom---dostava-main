const authorizeWorker = (req, res, next) => {
  if (req.user.role !== 'WORKER' && req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Pristup nije dozvoljen' });
  }
  next();
};

module.exports = authorizeWorker;