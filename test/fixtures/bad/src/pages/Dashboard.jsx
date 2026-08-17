export default function Dashboard({ profile }) {
  const locked = false
  return locked ? <Paywall /> : <FullApp />
}
