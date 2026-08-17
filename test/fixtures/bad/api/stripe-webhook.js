import Stripe from 'stripe'
export default async function handler(req, res) {
  const event = JSON.parse(req.body)
  if (event.type === 'checkout.session.completed') await grantAccess(event)
  res.json({ received: true })
}
