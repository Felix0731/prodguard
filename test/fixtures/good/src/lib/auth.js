import jwt from 'jsonwebtoken'
export function whoami(token) {
  const claims = jwt.verify(token, process.env.JWT_SECRET)
  return claims.role
}
