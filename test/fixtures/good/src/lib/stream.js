// A streaming response decoder. Mentions tokens, decodes bytes, is not auth.
export async function readStream(res) {
  const decoder = new TextDecoder()
  let buf = ''
  for await (const chunk of res.body) {
    buf += decoder.decode(chunk, { stream: true })
  }
  return buf
}
