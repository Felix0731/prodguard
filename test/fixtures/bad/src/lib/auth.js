import jwt from 'jsonwebtoken'
export function whoami(token) {
  const claims = jwt.decode(token)
  return claims.role
}
