// Role-based access control matching CloudSpy's VIEW_ACCESS from constants.js
const ACCESS = {
  all: ['security', 'engineer', 'contractor', 'finance'],
  security: ['security'],
  engineer: ['security', 'engineer'],
  finance: ['security', 'finance'],
  contractor: ['security', 'contractor'],
};

function allow(...roles) {
  const allowed = new Set(roles.flatMap(r => ACCESS[r] || [r]));
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (!allowed.has(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden: insufficient role' });
    }
    next();
  };
}

module.exports = { allow };
