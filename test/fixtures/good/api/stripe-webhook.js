import Stripe from 'stripe'
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY)
export default async function handler(req, res) {
  const sig = req.headers['stripe-signature']
  const event = stripe.webhooks.constructEvent(req.rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET)
  if (event.type === 'checkout.session.completed') await grantAccess(event)
  res.json({ received: true })
}
