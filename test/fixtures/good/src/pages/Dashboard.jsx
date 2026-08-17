export default function Dashboard({ profile }) {
  const locked = profile?.subscriptionStatus !== 'active'
  return locked ? <Paywall /> : <FullApp />
}
