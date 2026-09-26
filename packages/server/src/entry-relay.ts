import { createRelayServer } from "./relay.js";
import { readTrimmedEnv } from "./http.js";

/**
 * 中继形态入口（DESIGN v3.1 §1「[ECS] zcode-relay」）。
 *
 * 与 entry-http 的关键差异：不装配 createLocalServices —— ECS 上没有本地会话，
 * 既无用又省攻击面；进程只承担静态托管 web dist、host 注册表与挂载桥。
 *
 * 环境变量：
 *  - PORT / ZCODE_SERVER_HOST / HOST：监听端口（默认 3031，避开 entry-http 的 3030）与地址
 *  - ZCODE_WEB_STATIC_ROOT：web dist 根目录（SPA fallback，剔除 *.map）
 *  - ZCODE_SERVER_AUTH_TOKEN：lite token（网页门；Authelia 之后第二道）
 *  - ZCODE_REMOTE_ENROLL_TOKEN：enroll token（桌面桥准入；与 feed token 独立，绝不复用）
 */
async function main(): Promise<void> {
  const port = Number(process.env["PORT"]) || 3031;
  const host = readTrimmedEnv("ZCODE_SERVER_HOST") || readTrimmedEnv("HOST");
  const staticRoot = readTrimmedEnv("ZCODE_WEB_STATIC_ROOT");
  const authToken = readTrimmedEnv("ZCODE_SERVER_AUTH_TOKEN");
  const enrollToken = readTrimmedEnv("ZCODE_REMOTE_ENROLL_TOKEN");
  const trustAuthelia = readTrimmedEnv("ZCODE_RELAY_TRUST_AUTHELIA") === "1";

  createRelayServer(port, {
    ...(host ? { host } : {}),
    ...(staticRoot ? { staticRoot, spaFallback: true } : {}),
    ...(authToken ? { authToken } : {}),
    ...(enrollToken ? { enrollToken } : {}),
    ...(trustAuthelia ? { trustAuthelia } : {}),
  });
}

void main().catch((error: unknown) => {
  console.error("[zcode-relay] startup failed", error);
  process.exitCode = 1;
});
