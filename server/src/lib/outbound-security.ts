import { lookup as dnsLookup } from 'dns/promises'
import { isIP } from 'net'
import { Agent } from 'undici'
import type { LookupAddress } from 'dns'

export class OutboundTargetValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'OutboundTargetValidationError'
  }
}

type SupportedProtocol = 'http' | 'https' | 'ftp' | 'sftp'

function buildUrl(input: string, defaultProtocol: SupportedProtocol): URL {
  const trimmed = input.trim()
  if (!trimmed) {
    throw new OutboundTargetValidationError('Target cannot be empty')
  }

  try {
    if (trimmed.includes('://')) {
      return new URL(trimmed)
    }
    return new URL(`${defaultProtocol}://${trimmed}`)
  } catch {
    throw new OutboundTargetValidationError('Target format is invalid')
  }
}

function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, item) => (acc << 8) + Number(item), 0) >>> 0
}

function isIpv4InCidr(ip: string, baseIp: string, prefixLength: number): boolean {
  const ipInt = ipv4ToInt(ip)
  const baseInt = ipv4ToInt(baseIp)
  const mask = prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0
  return (ipInt & mask) === (baseInt & mask)
}

function normalizeIpv6(ip: string): string {
  return ip.toLowerCase().replace(/^\[|\]$/g, '')
}

function isIpv6PrivateOrReserved(ip: string): boolean {
  const normalized = normalizeIpv6(ip)

  if (
    normalized === '::' ||
    normalized === '::1' ||
    normalized.startsWith('fc') ||
    normalized.startsWith('fd') ||
    /^fe[89ab]/i.test(normalized) ||
    normalized.startsWith('ff') ||
    normalized.startsWith('2001:db8')
  ) {
    return true
  }

  const mappedIpv4Match = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i)
  if (mappedIpv4Match) {
    return isIpPrivateOrReserved(mappedIpv4Match[1])
  }

  return false
}

export function isIpPrivateOrReserved(ip: string): boolean {
  const family = isIP(ip)
  if (family === 4) {
    const ranges: Array<[string, number]> = [
      ['0.0.0.0', 8],
      ['10.0.0.0', 8],
      ['100.64.0.0', 10],
      ['127.0.0.0', 8],
      ['169.254.0.0', 16],
      ['172.16.0.0', 12],
      ['192.0.0.0', 24],
      ['192.0.2.0', 24],
      ['192.168.0.0', 16],
      ['198.18.0.0', 15],
      ['198.51.100.0', 24],
      ['203.0.113.0', 24],
      ['224.0.0.0', 4],
      ['240.0.0.0', 4]
    ]

    return ranges.some(([baseIp, prefixLength]) => isIpv4InCidr(ip, baseIp, prefixLength))
  }

  if (family === 6) {
    return isIpv6PrivateOrReserved(ip)
  }

  return true
}

async function assertPublicHostname(hostname: string): Promise<LookupAddress[]> {
  const normalizedHost = hostname.trim().toLowerCase().replace(/\.$/, '')
  if (!normalizedHost) {
    throw new OutboundTargetValidationError('Hostname cannot be empty')
  }

  if (
    normalizedHost === 'localhost' ||
    normalizedHost.endsWith('.localhost') ||
    normalizedHost.endsWith('.local') ||
    normalizedHost.endsWith('.internal')
  ) {
    throw new OutboundTargetValidationError('Private or local targets are not allowed')
  }

  const family = isIP(normalizedHost)
  if (family !== 0) {
    if (isIpPrivateOrReserved(normalizedHost)) {
      throw new OutboundTargetValidationError('Private or reserved IP targets are not allowed')
    }
    // 字面 IP：不会触发 DNS 解析，无重绑风险，直接固定该 IP
    return [{ address: normalizedHost, family }]
  }

  if (!normalizedHost.includes('.')) {
    throw new OutboundTargetValidationError('Private or local hostnames are not allowed')
  }

  let records: LookupAddress[]
  try {
    records = await dnsLookup(normalizedHost, { all: true, verbatim: true })
  } catch (error: any) {
    const code = error?.code ? String(error.code) : 'UNKNOWN'
    throw new OutboundTargetValidationError(`Unable to resolve hostname (${code})`)
  }

  if (records.length === 0) {
    throw new OutboundTargetValidationError('Unable to resolve hostname')
  }

  for (const record of records) {
    if (isIpPrivateOrReserved(record.address)) {
      throw new OutboundTargetValidationError('Targets resolving to private or reserved IPs are not allowed')
    }
  }

  // 返回已校验的解析结果，供调用方固定连接 IP（防 DNS Rebinding）
  return records
}

export async function assertSafeWebhookUrl(url: string): Promise<URL> {
  const parsed = buildUrl(url, 'https')
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new OutboundTargetValidationError('Webhook URL must use http or https')
  }

  await assertPublicHostname(parsed.hostname)
  return parsed
}

/**
 * 安全地向 Webhook 发起请求（防 SSRF + DNS Rebinding）。
 *
 * 关键点：assertSafeWebhookUrl 解析校验后，如果直接 fetch(url)，undici 会**重新做一次
 * DNS 解析**，攻击者控制的权威 DNS 可在两次解析之间把记录改成 127.0.0.1 / 169.254.169.254
 * 等内网地址（DNS Rebinding）绕过校验。这里把连接 IP **固定**为校验时解析到的地址，
 * 自定义 undici lookup 不再二次解析，从根本上杜绝重绑。
 */
export async function safeWebhookFetch(
  url: string,
  init: RequestInit = {}
): Promise<Response> {
  const parsed = buildUrl(url, 'https')
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new OutboundTargetValidationError('Webhook URL must use http or https')
  }

  const validatedAddresses = await assertPublicHostname(parsed.hostname)

  // 自定义 lookup：只返回校验通过的 IP，绝不二次解析
  const pinnedLookup = (
    _hostname: string,
    _options: unknown,
    callback: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void
  ): void => {
    callback(null, validatedAddresses)
  }

  const dispatcher = new Agent({
    connect: {
      lookup: pinnedLookup as never
    }
  })

  try {
    // @ts-expect-error undici 的 dispatcher 选项不在标准 RequestInit 类型里
    return await fetch(parsed.toString(), { ...init, dispatcher })
  } finally {
    await dispatcher.close().catch(() => {})
  }
}

export async function assertSafeStorageTarget(
  type: 'WEBDAV' | 'FTP' | 'SFTP',
  host: string
): Promise<void> {
  const defaultProtocol: Record<'WEBDAV' | 'FTP' | 'SFTP', SupportedProtocol> = {
    WEBDAV: 'https',
    FTP: 'ftp',
    SFTP: 'sftp'
  }

  const parsed = buildUrl(host, defaultProtocol[type])
  await assertPublicHostname(parsed.hostname)
}
