/**
 * Authorized network scope parsing, shared by the server action and the UI
 * preview. This deliberately allows only small private IPv4 ranges: the worker
 * re-validates the same policy before it runs Nmap.
 */

const ALLOWED_RANGES = [
  { network: "10.0.0.0", prefix: 8 },
  { network: "172.16.0.0", prefix: 12 },
  { network: "192.168.0.0", prefix: 16 },
  { network: "100.64.0.0", prefix: 10 },
] as const

const MIN_PREFIX = 24
const MAX_HOSTS = 256

export type NetworkScope = {
  /** Normalized network address, e.g. 192.168.1.0/24 */
  cidr: string
  prefix: number
  addressCount: number
  usableHosts: number
  firstAddress: string
  lastAddress: string
}

function ipv4ToInt(value: string): number | null {
  const parts = value.split(".")
  if (parts.length !== 4) return null

  let result = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const octet = Number(part)
    if (octet < 0 || octet > 255) return null
    result = result * 256 + octet
  }
  return result >>> 0
}

function intToIpv4(value: number): string {
  return [24, 16, 8, 0]
    .map((shift) => (value >>> shift) & 255)
    .join(".")
}

function maskForPrefix(prefix: number): number {
  if (prefix <= 0) return 0
  return (0xffffffff << (32 - prefix)) >>> 0
}

function insideRange(network: number, range: { network: string; prefix: number }) {
  const rangeNetwork = ipv4ToInt(range.network)
  if (rangeNetwork === null) return false
  const mask = maskForPrefix(range.prefix)
  return (network & mask) >>> 0 === (rangeNetwork & mask) >>> 0
}

export function parseNetworkScope(input: string): NetworkScope {
  const candidate = input.trim().toLowerCase()
  if (!candidate) throw new Error("Enter a CIDR range, for example 192.168.1.0/24.")

  const [address, prefixText, ...rest] = candidate.split("/")
  if (!address || prefixText === undefined || rest.length > 0) {
    throw new Error("Enter a CIDR range with a prefix, for example 192.168.1.0/24.")
  }
  if (!/^\d{1,2}$/.test(prefixText)) {
    throw new Error("The CIDR prefix must be a number between 24 and 32.")
  }

  const prefix = Number(prefixText)
  const ip = ipv4ToInt(address)
  if (ip === null) throw new Error("Enter a valid IPv4 address.")
  if (prefix < MIN_PREFIX || prefix > 32) {
    throw new Error(
      `The smallest network NeoShield will scan is a /${MIN_PREFIX}.`
    )
  }

  const mask = maskForPrefix(prefix)
  const network = (ip & mask) >>> 0
  const broadcast = (network | (~mask >>> 0)) >>> 0
  const addressCount = 2 ** (32 - prefix)

  if (addressCount > MAX_HOSTS) {
    throw new Error(`The range must contain at most ${MAX_HOSTS} addresses.`)
  }

  if (!ALLOWED_RANGES.some((range) => insideRange(network, range))) {
    throw new Error(
      "Only private RFC1918 or CGNAT ranges can be scanned (10/8, 172.16/12, 192.168/16, 100.64/10)."
    )
  }

  return {
    cidr: `${intToIpv4(network)}/${prefix}`,
    prefix,
    addressCount,
    usableHosts: Math.max(0, addressCount - 2),
    firstAddress: intToIpv4(network),
    lastAddress: intToIpv4(broadcast),
  }
}

export function networkScopeIsValid(input: string): boolean {
  try {
    parseNetworkScope(input)
    return true
  } catch {
    return false
  }
}
