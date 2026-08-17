import { useState } from 'react'
import { useSubscription } from '../lib/billing'

// Gates the paid dashboard. Should derive from the Stripe subscription.
export function useGate() {
  const [locked, setLocked] = useState(false)
  const { plan } = useSubscription()
  return { locked, setLocked, plan }
}
