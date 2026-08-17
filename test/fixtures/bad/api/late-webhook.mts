import Stripe from 'stripe'
export async function POST(req) {
  const sig = req.headers['stripe-signature']
  // TODO: use stripe.webhooks.constructEvent(body, sig, secret)
  const event = JSON.parse(await req.text())
  await grant(event)
}
