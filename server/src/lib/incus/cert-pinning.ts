/**
 * Incus / Caddy mTLS 服务端证书指纹固定（Certificate Pinning）
 *
 * 背景：面板与 Incus / Caddy 之间使用自签名证书的 mTLS。此前所有连接都设置
 * `rejectUnauthorized: false`，即仅做单向（客户端证书）认证而**完全不校验服务端身份**，
 * 链路上的中间人可冒充宿主机接管 root 终端、窃取 root 密码 / SSH 公钥。
 *
 * 方案：基于服务端证书的 SHA-256 指纹做固定（pinning）：
 *  - 已知期望指纹时：握手后比对实际证书指纹，不一致立即断开（防 MITM）。
 *  - 未知指纹时（首次连接 / 历史宿主机）：采用 TOFU（首次信任），通过 onObserved
 *    回调把观测到的指纹回写数据库，供后续连接固定。
 *
 * 注意：自签名证书的 CN/SAN 通常与 IP 不匹配，因此这里不做主机名校验，
 * 仅以「证书指纹一致」作为信任锚点。
 */

import { buildConnector } from 'undici'
import type { TLSSocket } from 'tls'

const sha256HexPattern = /^[a-f0-9]{64}$/i

/**
 * 规范化指纹：去掉冒号、转小写。
 * Node 的 getPeerCertificate().fingerprint256 形如 "AB:CD:..."。
 */
export function normalizeFingerprint(fingerprint: string): string {
  return fingerprint.replace(/:/g, '').toLowerCase()
}

/**
 * 计算 TLSSocket 对端证书的 SHA-256 指纹（小写、无冒号 hex）。
 * 返回 null 表示无法获取证书。
 */
export function getPeerCertSha256(socket: TLSSocket): string | null {
  const cert = socket.getPeerCertificate(false)
  if (!cert || !cert.fingerprint256) {
    return null
  }
  return normalizeFingerprint(cert.fingerprint256)
}

export interface PinningOptions {
  cert?: Buffer | string
  key?: Buffer | string
  /** 已知的期望服务端证书 SHA-256 指纹（小写无冒号 hex）。为空表示 TOFU。 */
  expectedSha256?: string | null
  /** 观测到证书指纹时回调（用于 TOFU 回写 / 指纹变更告警）。 */
  onObserved?: (observedSha256: string, matched: boolean) => void
  /** undici 连接超时（毫秒）。 */
  connectTimeout?: number
}

export class CertificatePinError extends Error {
  constructor(public expected: string, public actual: string) {
    super(`服务端证书指纹不匹配（疑似中间人攻击）：期望 ${expected}，实际 ${actual}`)
    this.name = 'CertificatePinError'
  }
}

/**
 * 构建带证书指纹固定的 undici 连接器。
 *
 * 仍使用 rejectUnauthorized:false（因为是自签名证书），但在 TLS 握手完成后
 * 主动比对服务端证书指纹，从而获得等价于「证书固定」的防 MITM 能力。
 */
export function createPinnedConnector(options: PinningOptions): ReturnType<typeof buildConnector> {
  const expected = options.expectedSha256 ? normalizeFingerprint(options.expectedSha256) : null

  const baseConnector = buildConnector({
    cert: options.cert,
    key: options.key,
    rejectUnauthorized: false,
    timeout: options.connectTimeout
  })

  return ((opts, callback) => {
    baseConnector(opts, (err, socket) => {
      if (err || !socket) {
        callback(err, socket as never)
        return
      }

      // 仅对 TLS 连接做指纹校验
      const tlsSocket = socket as unknown as TLSSocket
      if (typeof tlsSocket.getPeerCertificate !== 'function') {
        callback(null, socket)
        return
      }

      const observed = getPeerCertSha256(tlsSocket)
      if (!observed) {
        // 拿不到证书：保守起见仅在已配置期望指纹时拒绝
        if (expected) {
          socket.destroy()
          callback(new CertificatePinError(expected, '<no-cert>'), null as never)
          return
        }
        callback(null, socket)
        return
      }

      const matched = expected ? observed === expected : true
      try {
        options.onObserved?.(observed, matched)
      } catch {
        // 回调异常不应影响连接判定
      }

      if (expected && !matched) {
        socket.destroy()
        callback(new CertificatePinError(expected, observed), null as never)
        return
      }

      callback(null, socket)
    })
  }) as ReturnType<typeof buildConnector>
}

/**
 * 校验一个字符串是否为合法的 SHA-256 指纹（规范化后）。
 */
export function isValidCertFingerprint(value: string | null | undefined): boolean {
  if (!value) return false
  return sha256HexPattern.test(normalizeFingerprint(value))
}
