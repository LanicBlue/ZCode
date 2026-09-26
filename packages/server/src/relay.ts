/* eslint-disable max-lines -- 中继形态路由/注册表/挂载桥与设备页集中注册，保持同一鉴权顺序（K1 起文件已超 400 行，延续 http.ts 同款豁免）。 */
/**
 * zcode-relay —— packages/server 的「中继形态」入口装配（DESIGN v3.1 §1/§5-K1）。
 *
 * 与 entry-http（本地会话形态）的四条偏离，成清单（DESIGN §5-K1）：
 *  a) lite token 中间件对 /ws/host 与 /api/rpc-host-capability 做 carve-out：
 *     这两条是程序化桌面客户端路径，走 Bearer enroll token，不过 Authelia/lite token
 *     （上游 isTokenProtectedPath 覆盖 /ws* 与 /api*，会挡死桌面桥）。
 *  b) /api/rpc-host-capability 增加 Bearer enroll token 校验（上游完全无鉴权）。
 *  c) 无 local services：不装配 createLocalServices（ECS 上无本地会话），本模块
 *     只做静态托管 + host 注册表 + 挂载桥。
 *  d) attach 语义：/ws/remote/:deviceId 把 /ws/host 连入桌面的白名单服务桥给网页客户端
 *     （上游同路径桥的是 /api/connect-remote 建立的 SSH/WSL 远程连接，取出即销毁）。
 *
 * 硬约束（DESIGN §5-K1，全部满足）：
 *  - attach 复用 http.ts 的 setupChannelServer：LoggingChannelServer、connectionScope、
 *    非 desktop-continuous 禁 provisioning 的覆盖、exposeOnChannelServer 一字不改。
 *  - capability 沿用 createHostCapabilityStore：一次性 + 30s TTL + 防重放语义不变。
 *  - 挂载白名单永不包含 credential / provider-provisioning-target（DESIGN §3-3，
 *    双保险：桌面侧过滤注册 + 本侧硬排除）。oauth / provider-settings 只经设备侧
 *    脱敏包装放行（见 RELAY_FORBIDDEN_DEVICE_SERVICES 注释的信任模型）。
 */
import { readFile } from "node:fs/promises";
import { timingSafeEqual } from "node:crypto";
import { serve } from "@hono/node-server";
import { getConnInfo } from "@hono/node-server/conninfo";
import { createNodeWebSocket } from "@hono/node-ws";
import { Hono, type Context } from "hono";
import type { WebSocket } from "ws";
import { ChannelClient, ProxyChannel, SocketProtocol } from "@zcode/rpc";
import {
  ServiceCollection,
  IBroadcastService,
  ICredentialService,
  IFileService,
  IModelSelectionService,
  IOAuthService,
  IProviderProvisioningTargetService,
  IProviderSettingsService,
  ISettingService,
  ITerminalService,
  IZCodeAgentService,
  IZCodeSessionService,
  IZCodeTaskService,
  type ServiceDescriptor,
} from "@zcode/services";
import {
  formatLogPrefix,
  resolveStartupLocalWorkspaceSessionIndex,
  SERVER_REMOTE_PROTOCOL_VERSION,
  ZCODE_RPC_HOST_CAPABILITY_HEADER,
  ZCODE_VERSION,
  type AppSettings,
  type ServerRemoteInfo,
  type ServerRemoteWorkspaceInfo,
} from "@zcode/shared";
import { createHostCapabilityStore } from "./hostCapability.js";
import {
  hasValidLiteToken,
  isTokenProtectedPath,
  resolveStaticFile,
  setupChannelServer,
  staticContentType,
  wrapWebSocket,
} from "./http.js";

const log = (...args: unknown[]) =>
  console.log(formatLogPrefix("zcode-relay", process.pid), ...args);

/**
 * 中继侧连接心跳：设备/网页侧静默断网（NAT 超时、睡眠无 FIN）不会产生 close 帧，
 * 没有心跳的连接会以在线态永久滞留注册表（设备假在线、挂载/RPC 挂死，DESIGN §7
 * 「睡眠/离线→显示离线」落空）。每 tick 发 protocol ping，一整个间隔未 pong 即
 * terminate（close → unregister）。与设备桥侧 HEARTBEAT_INTERVAL_MS 对称，双向覆盖。
 */
const HOST_HEARTBEAT_INTERVAL_MS = 30_000;

function startWebSocketHeartbeat(raw: WebSocket): () => void {
  let alive = true;
  raw.on("pong", () => {
    alive = true;
  });
  const timer = setInterval(() => {
    if (raw.readyState !== raw.OPEN) {
      return;
    }
    if (!alive) {
      log(`host heartbeat timeout; terminating half-open connection`);
      try {
        raw.terminate();
      } catch {
        // 已断开；close 事件自会走 unregister。
      }
      clearInterval(timer);
      return;
    }
    alive = false;
    raw.ping();
  }, HOST_HEARTBEAT_INTERVAL_MS);
  timer.unref?.();
  return () => clearInterval(timer);
}

/**
 * 凭据邻接面：任何挂载白名单都不得包含（含配置面错误也直接拒绝启动）。
 * DESIGN §3-3「全量减 ICredentialService 减 IProviderProvisioningTarget 减 IOAuthService」。
 * 信任模型更新：oauth / provider-settings 已从双侧一刀切硬禁改为「只许设备侧脱敏包装」——
 * host 是信任锚，脱敏/只读保证在 desktop/src/host/remoteBridge.ts 结构化强制
 * （REMOTE_BRIDGE_REDACTED_CHANNELS + registerRedactedChannel brand 校验，raw 实例注册
 * 即 fail）。relay 在这两条通道上只做透明转发，不再重复拦（重复拦会让包装后的合法
 * 调用也打不通）；credential / provider-provisioning-target 维持双侧硬禁，
 * 桌面侧镜像清单见 remoteBridge.ts REMOTE_BRIDGE_FORBIDDEN_CHANNEL_NAMES。
 */
export const RELAY_FORBIDDEN_DEVICE_SERVICES: readonly ServiceDescriptor<unknown>[] = [
  ICredentialService,
  IProviderProvisioningTargetService,
];

/**
 * K2 定案的最小必需集（DESIGN §5-K2 + K3 复核）= 桌面桥 REMOTE_BRIDGE_SERVICE_WHITELIST
 * 的同构清单：setting/modelSelection/agent/session/task/file/terminal/broadcast。
 * modelSelection 的 apiKey-redaction 在设备侧注册面完成（remoteBridge.ts）；
 * oauth / provider-settings 同理由设备侧分别以只读/脱敏包装注册（见上信任模型注释），
 * 这里挂的是同名通道的透明代理。IGitService / ISystemService 未入最小集（缺=降级不挂，
 * K2 实测）；可用 RelayServerOptions.deviceServiceWhitelist 覆盖做实验，但与上面
 * 禁入清单求交永远为空。
 */
export const DEFAULT_RELAY_DEVICE_SERVICE_WHITELIST: readonly ServiceDescriptor<unknown>[] = [
  ISettingService,
  IModelSelectionService,
  IZCodeAgentService,
  IZCodeSessionService,
  IZCodeTaskService,
  IFileService,
  ITerminalService,
  IBroadcastService,
  IOAuthService,
  IProviderSettingsService,
];

/** /devices 列表项（JSON API 与小页共用形状）。 */
export interface RelayDeviceInfo {
  deviceMid: string;
  hostname: string;
  online: boolean;
  connectedAt?: number;
  lastSeenAt: number;
}

interface RelayHostEntry {
  readonly deviceMid: string;
  readonly hostname: string;
  readonly connectedAt: number;
  readonly client: ChannelClient;
  readonly socket: WebSocket;
}

/**
 * host 注册表：连入桌面（/ws/host）记录设备身份，供 /devices 列出与 attach 查找。
 * 断线仅转离线态不遗忘（内存态；relay 无状态、重启即清空，DESIGN §6）；
 * 离线记忆有上限淘汰，防持 enroll token 方用随机 deviceMid 把 seen 无界撑大
 * （ECS 小内存机上的慢速内存放大）。
 */
interface RelayHostRegistry {
  register(entry: RelayHostEntry): void;
  unregister(entry: RelayHostEntry): void;
  getOnline(deviceMid: string): RelayHostEntry | undefined;
  list(): RelayDeviceInfo[];
}

/** 离线设备记忆上限（在线条目不参与淘汰；超出后按最久未见先逐出）。 */
const MAX_REMEMBERED_OFFLINE_HOSTS = 4_096;

function createRelayHostRegistry(): RelayHostRegistry {
  const live = new Map<string, RelayHostEntry>();
  const seen = new Map<string, { hostname: string; lastSeenAt: number }>();
  const evictStaleSeen = (): void => {
    for (const deviceMid of seen.keys()) {
      if (seen.size <= MAX_REMEMBERED_OFFLINE_HOSTS) {
        return;
      }
      if (live.has(deviceMid)) {
        continue;
      }
      seen.delete(deviceMid);
    }
  };
  return {
    register(entry) {
      const previous = live.get(entry.deviceMid);
      if (previous && previous !== entry) {
        // 同一 deviceMid 重连（桥重启/网络切换）：新连接接管，旧的按掉线收口。
        log(`host takeover deviceMid=${entry.deviceMid}`);
        previous.socket.close(4001, "Replaced by a newer host connection");
      }
      live.set(entry.deviceMid, entry);
      seen.set(entry.deviceMid, { hostname: entry.hostname, lastSeenAt: Date.now() });
      evictStaleSeen();
    },
    unregister(entry) {
      if (live.get(entry.deviceMid) !== entry) {
        return;
      }
      live.delete(entry.deviceMid);
      seen.set(entry.deviceMid, { hostname: entry.hostname, lastSeenAt: Date.now() });
      evictStaleSeen();
      log(`host disconnected deviceMid=${entry.deviceMid}`);
    },
    getOnline(deviceMid) {
      return live.get(deviceMid);
    },
    list() {
      const devices: RelayDeviceInfo[] = [];
      for (const [deviceMid, entry] of live) {
        devices.push({
          deviceMid,
          hostname: entry.hostname,
          online: true,
          connectedAt: entry.connectedAt,
          lastSeenAt: Date.now(),
        });
      }
      for (const [deviceMid, record] of seen) {
        if (live.has(deviceMid)) {
          continue;
        }
        devices.push({
          deviceMid,
          hostname: record.hostname,
          online: false,
          lastSeenAt: record.lastSeenAt,
        });
      }
      devices.sort((a, b) => a.deviceMid.localeCompare(b.deviceMid));
      return devices;
    },
  };
}

export interface RelayServerOptions {
  host?: string;
  /** 桌面桥准入（Bearer enroll token；ZCODE_REMOTE_ENROLL_TOKEN）。缺失时 fail-closed。 */
  enrollToken?: string;
  /** 网页 lite token（ZCODE_SERVER_AUTH_TOKEN）；缺失时不设 lite token 门（生产由 Authelia 前置）。 */
  authToken?: string;
  /** 信任 forward_auth 注入的 Remote-User 头（ZCODE_RELAY_TRUST_AUTHELIA=1）：浏览器路径过门即通行。 */
  trustAuthelia?: boolean;
  staticRoot?: string;
  spaFallback?: boolean;
  /** K2 实验用白名单覆盖；默认 DEFAULT_RELAY_DEVICE_SERVICE_WHITELIST。 */
  deviceServiceWhitelist?: readonly ServiceDescriptor<unknown>[];
  /**
   * capability 发放限流（每分钟每来源 IP），默认 120。设备重连风暴（relay 重启全员
   * 重连）按每人每连接 1 张票计，120/min 对个人机队余量充足，同时封死持 token 的高频
   * 取票抖动。设 0 关闭。
   */
  capabilityRateLimitPerMinute?: number;
}

function isTokenEqual(presented: string, expected: string): boolean {
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** 程序化客户端的 Bearer enroll token 校验（DESIGN §3-1）。 */
function hasValidBearerToken(c: Context, token: string): boolean {
  const header = c.req.header("authorization");
  if (!header?.startsWith("Bearer ")) {
    return false;
  }
  return isTokenEqual(header.slice("Bearer ".length).trim(), token);
}

/**
 * capability 发放的固定窗口限流（按来源 IP）。enroll token 烧进每个分发包、可从包内
 * 提取，单靠 token 门挡不住高频取票把注册表抖成互殴（F10 连接抖动面）或慢速资源
 * 消耗；capability 一次性消费=每个 /ws/host 升级都先过这里，卡住取票即卡住建连。
 */
interface FixedWindowRateLimiter {
  allow(key: string): boolean;
}

function createFixedWindowRateLimiter(max: number, windowMs: number): FixedWindowRateLimiter {
  const windows = new Map<string, { startedAt: number; count: number }>();
  return {
    allow(key) {
      const now = Date.now();
      const current = windows.get(key);
      if (!current || now - current.startedAt >= windowMs) {
        // 惰性窗口轮转：键数受 IP 数上界约束，超限整体重置防限流表自身被撑爆。
        if (windows.size > 10_000) {
          windows.clear();
        }
        windows.set(key, { startedAt: now, count: 1 });
        return true;
      }
      current.count += 1;
      return current.count <= max;
    },
  };
}

/** 桌面桥专用路径（走 enroll token 区，lite token 中间件放行）。 */
function isEnrollTokenPath(pathname: string): boolean {
  return pathname === "/ws/host" || pathname === "/api/rpc-host-capability";
}

function registerDeviceServiceProxies(
  services: ServiceCollection,
  client: ChannelClient,
  descriptors: readonly ServiceDescriptor<unknown>[],
): void {
  for (const descriptor of descriptors) {
    // 与 http.ts /ws/remote 相同的桥接形状：ChannelClient 代理经 ProxyChannel 重挂给网页。
    services.register(
      descriptor as ServiceDescriptor<object>,
      ProxyChannel.toService<object>(client.getChannel(descriptor.channelName)),
    );
  }
}

function readDeviceIdentity(c: Context): { deviceMid: string; hostname: string } | undefined {
  const url = new URL(c.req.url);
  const deviceMid = (url.searchParams.get("deviceMid") ?? "").trim();
  const hostname = (url.searchParams.get("hostname") ?? "").trim();
  if (!deviceMid || deviceMid.length > 200 || hostname.length > 256) {
    return undefined;
  }
  return { deviceMid, hostname };
}

/** 设备侧 RPC 兜底超时：桥刚重连/服务未就绪时不能让 HTTP 请求无限挂起。 */
function withDeviceRpcTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`device rpc timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    timer.unref?.();
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}

/**
 * 把设备 AppSettings 投影为 web bootstrap 的工作区列表：本地 session 按桌面启动语义
 * active 优先（shared resolveStartupLocalWorkspaceSessionIndex 同款排序），再补
 * recentProjects；remote session 不进列表（web 远控形态 allowRemoteWorkspace=false）。
 */
function resolveDeviceWorkspaces(
  settings: Pick<AppSettings, "lastWorkspaceSession" | "lastActiveTabIndex" | "recentProjects">,
): ServerRemoteWorkspaceInfo[] {
  const sessions = settings.lastWorkspaceSession ?? [];
  const activeIndex = resolveStartupLocalWorkspaceSessionIndex(
    sessions,
    settings.lastActiveTabIndex,
  );
  const activeSession = activeIndex == null ? undefined : sessions[activeIndex];
  const orderedSessions = activeSession
    ? [activeSession, ...sessions.filter((session) => session !== activeSession)]
    : sessions;
  const workspaces: ServerRemoteWorkspaceInfo[] = [];
  const seen = new Set<string>();
  for (const session of orderedSessions) {
    if (session.kind !== "local" || !session.workspacePath || seen.has(session.workspacePath)) {
      continue;
    }
    seen.add(session.workspacePath);
    workspaces.push({ path: session.workspacePath });
  }
  for (const path of settings.recentProjects ?? []) {
    if (!path || seen.has(path)) {
      continue;
    }
    seen.add(path);
    workspaces.push({ path });
  }
  return workspaces;
}

export function createRelayServer(port = 3031, options: RelayServerOptions = {}) {
  const whitelist = options.deviceServiceWhitelist ?? DEFAULT_RELAY_DEVICE_SERVICE_WHITELIST;
  const forbiddenChannelNames = new Set(RELAY_FORBIDDEN_DEVICE_SERVICES.map((d) => d.channelName));
  for (const descriptor of whitelist) {
    if (forbiddenChannelNames.has(descriptor.channelName)) {
      throw new Error(
        `Relay device service whitelist must not include credential-adjacent service: ${descriptor.channelName}`,
      );
    }
  }

  const app = new Hono();
  const { injectWebSocket, upgradeWebSocket } = createNodeWebSocket({ app });
  const hostCapabilities = createHostCapabilityStore();
  const registry = createRelayHostRegistry();

  const enrollToken = options.enrollToken?.trim();
  if (!enrollToken) {
    log("ZCODE_REMOTE_ENROLL_TOKEN 未配置；capability 发放 fail-closed（设备无法注册）");
  }
  const authToken = options.authToken?.trim();

  // 偏离 a)：lite token 门 + /ws/host、/api/rpc-host-capability 的 carve-out。
  // trustAuthelia 时浏览器路径额外接受 forward_auth 注入的 Remote-User 头——过门
  // 即通行，无需任何 ?token= 激活链接。伪造不可行：该头只在过门路径上由 Caddy
  // copy_headers 覆盖注入；桥路径不走 forward_auth，其鉴权只认 Bearer，不看此头。
  const autheliaTrusted = options.trustAuthelia === true;
  if (authToken || autheliaTrusted) {
    app.use("*", async (c, next) => {
      const pathname = new URL(c.req.url).pathname;
      const passesLiteGate =
        isEnrollTokenPath(pathname) ||
        !isTokenProtectedPath(pathname) ||
        (authToken ? hasValidLiteToken(c, authToken) : false) ||
        (autheliaTrusted &&
          !isEnrollTokenPath(pathname) &&
          Boolean(c.req.header("Remote-User")?.trim()));
      if (passesLiteGate) {
        await next();
        return;
      }
      return c.json({ error: "Unauthorized" }, 401);
    });
  }

  // 偏离 b)：capability 端点必须持 Bearer enroll token 才发放（上游无鉴权），
  // 并按来源 IP 限流（见 createFixedWindowRateLimiter 注释）。
  const capabilityRateLimit = options.capabilityRateLimitPerMinute ?? 120;
  const capabilityLimiter =
    capabilityRateLimit > 0 ? createFixedWindowRateLimiter(capabilityRateLimit, 60_000) : null;
  app.post("/api/rpc-host-capability", (c) => {
    if (!enrollToken) {
      return c.json({ error: "Enroll token not configured" }, 503);
    }
    if (!hasValidBearerToken(c, enrollToken)) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    if (capabilityLimiter && !capabilityLimiter.allow(getConnInfo(c).remote.address ?? "unknown")) {
      return c.json({ error: "Too many capability requests" }, 429);
    }
    return c.json(hostCapabilities.issue());
  });

  app.get("/api/devices", (c) => c.json({ devices: registry.list() }));

  // Web 远控引导（DESIGN §5-K3 web 侧）：/?remote=<deviceId> 的 bootstrap 经本端点取
  // 桌面侧工作区信息合成 initialWorkspaceAbsPath（上游 main.tsx TODO 自认会卡首屏）。
  // 浏览器路径：lite token 门覆盖 /api*；只回工作区投影，不透出整份 AppSettings。
  app.get("/api/remote/:deviceId/server-info", async (c) => {
    const deviceId = c.req.param("deviceId");
    const entry = deviceId ? registry.getOnline(deviceId) : undefined;
    if (!entry) {
      return c.json({ error: "Device not found or offline" }, 404);
    }
    try {
      const settingService = ProxyChannel.toService<ISettingService>(
        entry.client.getChannel(ISettingService.channelName),
      );
      const settings = await withDeviceRpcTimeout(settingService.get(), 8_000);
      const info: ServerRemoteInfo = {
        serverId: `zcode-relay:${deviceId}`,
        name: entry.hostname,
        version: ZCODE_VERSION,
        protocolVersion: SERVER_REMOTE_PROTOCOL_VERSION,
        authRequired: Boolean(authToken),
        workspaces: resolveDeviceWorkspaces(settings),
        capabilities: { desktopContinuous: true, websocketRpc: true },
      };
      return c.json(info);
    } catch (error) {
      log(`device server-info failed deviceMid=${deviceId}:`, error);
      return c.json({ error: "Device workspace lookup failed" }, 502);
    }
  });

  app.get("/devices", (c) => {
    // 首访 ?token= 时顺手换 HttpOnly cookie，让小页的 /api/devices 与后续 /?remote= 直接过门。
    if (authToken) {
      hasValidLiteToken(c, authToken);
    }
    return c.html(renderDevicesPage());
  });

  // 桌面桥接入。capability 语义与上游一致：一次性 + TTL + 防重放（consume 即删）。
  app.use("/ws/host", async (c, next) => {
    if (!readDeviceIdentity(c)) {
      return c.json({ error: "Missing or invalid deviceMid/hostname" }, 400);
    }
    const capability = c.req.header(ZCODE_RPC_HOST_CAPABILITY_HEADER);
    if (!hostCapabilities.consume(capability)) {
      return c.json({ error: "Invalid or expired host capability" }, 401);
    }
    await next();
  });
  app.get(
    "/ws/host",
    upgradeWebSocket((c) => {
      const identity = readDeviceIdentity(c);
      return {
        onOpen(_event, ws) {
          const raw = ws.raw as WebSocket;
          if (!identity) {
            raw.close(4000, "Missing device identity");
            return;
          }
          // 中继是桌面白名单服务的消费方：桌面侧跑 ChannelServer（K3 桥），
          // 这里建 ChannelClient 并入注册表，等 attach 时再重挂给网页。
          const socket = wrapWebSocket(raw);
          const protocol = new SocketProtocol(socket);
          const client = new ChannelClient(protocol);
          const entry: RelayHostEntry = {
            deviceMid: identity.deviceMid,
            hostname: identity.hostname,
            connectedAt: Date.now(),
            client,
            socket: raw,
          };
          registry.register(entry);
          const stopHeartbeat = startWebSocketHeartbeat(raw);
          raw.on("close", stopHeartbeat);
          socket.onClose(() => {
            registry.unregister(entry);
            client.dispose(new Error("device host connection closed"));
            protocol.dispose();
          });
          log(`host connected deviceMid=${identity.deviceMid} hostname=${identity.hostname}`);
        },
      };
    }),
  );

  // 偏离 d)：attach。设备在线时把其白名单服务桥给网页；硬约束=复用 setupChannelServer，
  // "web-remote-replayable" 路径上的 provisioning 禁用覆盖随之生效。
  app.get(
    "/ws/remote/:deviceId",
    upgradeWebSocket((c) => {
      const deviceId = c.req.param("deviceId");
      return {
        onOpen(_event, ws) {
          const entry = deviceId ? registry.getOnline(deviceId) : undefined;
          if (!entry) {
            ws.close(4004, "Device not found or offline");
            return;
          }
          const services = new ServiceCollection();
          registerDeviceServiceProxies(services, entry.client, whitelist);
          setupChannelServer(ws.raw as WebSocket, services, "web-remote-replayable");
          // 挂载连接同样有心跳：移动网络静默断开后不再挂死设备侧连接 scope。
          const stopHeartbeat = startWebSocketHeartbeat(ws.raw as WebSocket);
          (ws.raw as WebSocket).on("close", stopHeartbeat);
        },
      };
    }),
  );

  // 偏离 c)：不装配 createLocalServices；静态托管复用上游路径穿越防护与 SPA fallback，
  // 另按 DESIGN §1 剔除 *.map（sourcemap 不出公网）。/devices 等具名路由在前，不会被吞。
  if (options.staticRoot?.trim()) {
    const staticRoot = options.staticRoot.trim();
    const spaFallback = options.spaFallback ?? true;
    app.get("*", async (c) => {
      const pathname = new URL(c.req.url).pathname;
      // 后缀判定必须与 resolveStaticFile 内部的 decodeURIComponent 对齐：URL.pathname
      // 保留 %2E 等编码，只看原始串会被 %2Emap 绕过（decode 后命中真实 .map）。
      // 判两层：解码形态（与落盘读取一致）+ 兜底看最终解析出的文件路径后缀。
      let decodedPathname = pathname;
      try {
        decodedPathname = decodeURIComponent(pathname);
      } catch {
        return c.notFound();
      }
      if (
        pathname.toLowerCase().endsWith(".map") ||
        decodedPathname.toLowerCase().endsWith(".map")
      ) {
        return c.notFound();
      }
      const filePath = await resolveStaticFile(staticRoot, pathname, spaFallback);
      if (!filePath || filePath.toLowerCase().endsWith(".map")) {
        return c.notFound();
      }
      return c.body(await readFile(filePath), 200, {
        "Cache-Control": filePath.endsWith("index.html")
          ? "no-cache"
          : "public, max-age=31536000, immutable",
        "Content-Type": staticContentType(filePath),
      });
    });
  }

  const server = serve({ fetch: app.fetch, hostname: options.host, port }, () => {
    const address = server.address();
    const listenPort = typeof address === "object" && address ? address.port : port;
    const listenHost = options.host?.trim() || "localhost";
    log(`http://${listenHost}:${listenPort}`);
  });

  injectWebSocket(server);

  return server;
}

function renderDevicesPage(): string {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZCode 设备</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.6 system-ui, sans-serif; margin: 0; padding: 32px 16px; }
  main { max-width: 640px; margin: 0 auto; }
  h1 { font-size: 20px; }
  ul { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }
  li a { display: flex; gap: 12px; align-items: center; padding: 12px 16px; border: 1px solid color-mix(in srgb, currentColor 20%, transparent); border-radius: 10px; text-decoration: none; color: inherit; }
  li a:hover { border-color: currentColor; }
  .dot { width: 10px; height: 10px; border-radius: 999px; background: #888; flex: none; }
  .dot.online { background: #2e9e5b; }
  .name { font-weight: 600; }
  .mid { font-family: ui-monospace, monospace; font-size: 12px; opacity: 0.7; overflow-wrap: anywhere; }
  .state { margin-left: auto; font-size: 12px; opacity: 0.7; flex: none; }
  p.hint { opacity: 0.7; font-size: 13px; }
</style>
</head>
<body>
<main>
<h1>ZCode 设备</h1>
<p class="hint">点击在线设备进入其桌面会话（/?remote=&lt;设备 ID&gt;）。</p>
<ul id="devices"></ul>
<p class="hint" id="error" hidden></p>
</main>
<script>
// 数据一律走 textContent 渲染：deviceMid/hostname 来自设备侧，不得进 innerHTML。
async function refresh() {
  const list = document.getElementById("devices");
  const error = document.getElementById("error");
  try {
    const res = await fetch("/api/devices", { headers: { accept: "application/json" } });
    if (res.status === 401) {
      error.hidden = false;
      error.textContent = "未授权：请带 lite token 访问（/devices?token=…）或先通过访问门。";
      list.replaceChildren();
      return;
    }
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    error.hidden = true;
    const items = (data.devices || []).map((device) => {
      const link = document.createElement("a");
      link.href = "/?remote=" + encodeURIComponent(device.deviceMid);
      if (!device.online) {
        link.setAttribute("aria-disabled", "true");
        link.style.opacity = "0.5";
        link.style.pointerEvents = "none";
      }
      const dot = document.createElement("span");
      dot.className = "dot" + (device.online ? " online" : "");
      const name = document.createElement("span");
      name.className = "name";
      name.textContent = device.hostname || device.deviceMid;
      const mid = document.createElement("span");
      mid.className = "mid";
      mid.textContent = device.deviceMid;
      const state = document.createElement("span");
      state.className = "state";
      state.textContent = device.online ? "在线" : "离线";
      link.append(dot, name, mid, state);
      const item = document.createElement("li");
      item.appendChild(link);
      return item;
    });
    list.replaceChildren(...items);
  } catch (err) {
    error.hidden = false;
    error.textContent = "加载失败：" + (err && err.message ? err.message : err);
  }
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>`;
}
