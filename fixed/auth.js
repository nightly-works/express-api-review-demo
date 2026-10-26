import jwt from 'jsonwebtoken';

// The secret must come from the environment: a fallback string in the code is public
// to anyone who has seen the repository, and would let them sign their own tokens.
export function loadSecret(value = process.env.JWT_SECRET) {
  if (!value || Buffer.byteLength(value) < 32) {
    throw new Error('JWT_SECRET must be set to at least 32 random bytes');
  }
  return value;
}

export function createAuth(db, secretFromConfig) {
  const secret = loadSecret(secretFromConfig);
  // The token names the user and the token version only. Role and workspace are read
  // from the database on each request, so a demotion or a password reset applies at once.
  function signToken(user) {
    return jwt.sign({ sub: String(user.id), tv: user.token_version }, secret, {
      algorithm: 'HS256',
      expiresIn: '7d',
    });
  }

  function requireAuth(req, res, next) {
    const match = /^Bearer (\S+)$/.exec(req.headers.authorization || '');
    if (!match) return res.status(401).json({ error: 'Unauthorized' });
    let claims;
    try {
      claims = jwt.verify(match[1], secret, { algorithms: ['HS256'] });
    } catch {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const user = db
      .prepare('SELECT id, email, name, role, workspace_id, token_version FROM users WHERE id = ?')
      .get(Number(claims.sub));
    if (!user || user.token_version !== claims.tv) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    req.user = user;
    next();
  }

  return { signToken, requireAuth };
}
