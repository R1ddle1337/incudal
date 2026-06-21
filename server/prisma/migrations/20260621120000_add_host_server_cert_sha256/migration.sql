-- 为宿主机增加服务端证书 SHA-256 指纹字段，用于 Incus/Caddy mTLS 的证书固定（TOFU 防 MITM）
ALTER TABLE "Host" ADD COLUMN "server_cert_sha256" TEXT;
