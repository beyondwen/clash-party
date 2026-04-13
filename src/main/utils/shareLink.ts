import { stringify } from './yaml'

const HY2_SCHEME_RE = /^(?:hysteria2|hy2):\/\//i
const PORT_SPEC_RE = /^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$/

interface IParsedShareLinkProfile {
  name: string
  content: string
}

interface IParsedHy2Proxy {
  name: string
  type: 'hysteria2'
  server: string
  port?: number
  ports?: string
  password: string
  sni?: string
  alpn?: string[]
  obfs?: string
  'obfs-password'?: string
  'skip-cert-verify'?: boolean
  fingerprint?: string
}

function decodeSafely(value: string): string {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

function parseBooleanFlag(value: string | null): boolean | undefined {
  if (value === null) return undefined
  const normalized = value.trim().toLowerCase()
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false
  return undefined
}

function parseHostAndPort(authority: string): { host: string; portSpec?: string } {
  if (!authority) {
    throw new Error('Invalid Hysteria2 link: missing server address')
  }

  if (authority.startsWith('[')) {
    const closingBracketIndex = authority.indexOf(']')
    if (closingBracketIndex === -1) {
      throw new Error('Invalid Hysteria2 link: malformed IPv6 server address')
    }

    const host = authority.slice(1, closingBracketIndex).trim()
    const portSpec = authority.slice(closingBracketIndex + 1).replace(/^:/, '').trim()
    return { host, portSpec: portSpec || undefined }
  }

  const lastColonIndex = authority.lastIndexOf(':')
  if (lastColonIndex === -1) {
    return { host: authority.trim() }
  }

  return {
    host: authority.slice(0, lastColonIndex).trim(),
    portSpec: authority.slice(lastColonIndex + 1).trim() || undefined
  }
}

function validatePortSpec(portSpec: string): void {
  if (!PORT_SPEC_RE.test(portSpec)) {
    throw new Error('Invalid Hysteria2 link: unsupported port format')
  }

  for (const segment of portSpec.split(',')) {
    const [startText, endText] = segment.split('-')
    const start = Number(startText)
    const end = endText ? Number(endText) : start

    if (
      Number.isNaN(start) ||
      Number.isNaN(end) ||
      start < 1 ||
      start > 65535 ||
      end < 1 ||
      end > 65535 ||
      start > end
    ) {
      throw new Error('Invalid Hysteria2 link: port is out of range')
    }
  }
}

function parseAlpnValues(searchParams: URLSearchParams): string[] | undefined {
  const rawValues = searchParams.getAll('alpn')
  const parsed = rawValues
    .flatMap((value) => value.split(','))
    .map((value) => decodeSafely(value.trim()))
    .filter(Boolean)

  return parsed.length > 0 ? [...new Set(parsed)] : undefined
}

function buildProfileContent(proxy: IParsedHy2Proxy): string {
  const groupName = proxy.name.toUpperCase() === 'PROXY' ? 'PROXY-GROUP' : 'PROXY'

  return stringify({
    proxies: [proxy],
    'proxy-groups': [
      {
        name: groupName,
        type: 'select',
        proxies: [proxy.name, 'DIRECT']
      }
    ],
    rules: [`MATCH,${groupName}`]
  })
}

export function isSupportedShareLink(url: string | undefined): boolean {
  return HY2_SCHEME_RE.test(url?.trim() || '')
}

export function parseShareLinkProfile(url: string): IParsedShareLinkProfile {
  const trimmed = url.trim()
  if (!HY2_SCHEME_RE.test(trimmed)) {
    throw new Error('Unsupported share link')
  }

  const withoutScheme = trimmed.replace(HY2_SCHEME_RE, '')
  const hashIndex = withoutScheme.indexOf('#')
  const beforeHash = hashIndex === -1 ? withoutScheme : withoutScheme.slice(0, hashIndex)
  const rawHash = hashIndex === -1 ? '' : withoutScheme.slice(hashIndex + 1)

  const queryIndex = beforeHash.indexOf('?')
  const beforeQuery = queryIndex === -1 ? beforeHash : beforeHash.slice(0, queryIndex)
  const rawQuery = queryIndex === -1 ? '' : beforeHash.slice(queryIndex + 1)

  const slashIndex = beforeQuery.indexOf('/')
  const authority = (slashIndex === -1 ? beforeQuery : beforeQuery.slice(0, slashIndex)).trim()

  const atIndex = authority.lastIndexOf('@')
  if (atIndex === -1) {
    throw new Error('Invalid Hysteria2 link: missing password')
  }

  const rawPassword = authority.slice(0, atIndex).trim()
  const hostAndPort = authority.slice(atIndex + 1).trim()
  const password = decodeSafely(rawPassword)
  const { host, portSpec } = parseHostAndPort(hostAndPort)

  if (!password) {
    throw new Error('Invalid Hysteria2 link: missing password')
  }
  if (!host) {
    throw new Error('Invalid Hysteria2 link: missing server address')
  }

  const searchParams = new URLSearchParams(rawQuery)
  const name = decodeSafely(rawHash) || `Hysteria2-${host}`
  const alpn = parseAlpnValues(searchParams)
  const skipCertVerify = parseBooleanFlag(searchParams.get('insecure'))
  const sni = searchParams.get('sni') || searchParams.get('server') || undefined
  const obfs = searchParams.get('obfs') || undefined
  const obfsPassword =
    searchParams.get('obfs-password') || searchParams.get('obfs_password') || undefined
  const fingerprint = searchParams.get('pinSHA256') || undefined

  const proxy: IParsedHy2Proxy = {
    name,
    type: 'hysteria2',
    server: host,
    password
  }

  if (portSpec) {
    validatePortSpec(portSpec)
    if (portSpec.includes(',') || portSpec.includes('-')) {
      proxy.ports = portSpec
    } else {
      proxy.port = Number(portSpec)
    }
  } else {
    proxy.port = 443
  }

  if (sni) proxy.sni = decodeSafely(sni)
  if (alpn) proxy.alpn = alpn
  if (obfs) proxy.obfs = decodeSafely(obfs)
  if (obfsPassword) proxy['obfs-password'] = decodeSafely(obfsPassword)
  if (fingerprint) proxy.fingerprint = decodeSafely(fingerprint)
  if (skipCertVerify !== undefined) {
    proxy['skip-cert-verify'] = skipCertVerify
  }

  return {
    name,
    content: buildProfileContent(proxy)
  }
}
