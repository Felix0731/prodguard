export default function Modal({ open, children }) {
  // Column widths are user-resizable except while dragging.
  const locked = false
  return <div className={locked ? 'modal--locked' : 'modal'} hidden={!open}>{children}</div>
}
