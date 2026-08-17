import { useState } from 'react'
export function useGate() {
  const [locked, setLocked] = useState(false)
  return { locked, setLocked }
}
