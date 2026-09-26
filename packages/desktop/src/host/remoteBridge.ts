/* eslint-disable max-lines -- K3 桥安全边界（白名单+redaction+心跳+重连编排）集中单文件，拆散反而扩大对抗审查面。 */
/**
 * 远控桥（zcode-web-selfhost DESIGN v3.1 §5-K3）—— 设备侧常驻连接模块。
 *
 * 运行位置：main 经 `spawnRemoteBridgeHostProcess` fork 的【无窗口专用 host】
 * （DESIGN 附录 A 拓扑定案；env `ZCODE_REMOTE_BRIDGE_HOST=1` 标记身份）。本模块只在该
 * 专用 host 内启动，窗口 host 完全不加载（host/index.ts 动态 import 门控）。
 *
 * 连接编排：POST {server}/api/rpc-host-capability（Bearer enroll token，构建期烧入）
 *   → 30s TTL 内连 WS {server}/ws/host?deviceMid=…&hostname=…（capability header）
 *   → 在 ws 上建 ChannelServer，只注册本文件白名单内的服务
 *   → 断线后抖动退避重连（full jitter，防雷群）；relay 重启自愈由此获得。
 *
 * ── 安全边界（对抗审查硬验收项，DESIGN §3-3 / §7）──────────────────────────────
 * 1. `REMOTE_BRIDGE_SERVICE_WHITELIST` + `registerWhitelistedChannels` 是【唯一】注册面：
 *    向 channel 注册的服务只有 K2 定案的 8 个最小集。凭据邻接四件套
 *    ICredentialService / IOAuthService / IProviderProvisioningTargetService /
 *    IProviderSettingsService 硬排除（`assertWhitelistExcludesForbiddenServices` 启动即校验）。
 * 2. IModelSelectionService 必须经 `createRedactedModelSelectionService` 包装：
 *    getView()/onDidChange 的 providers[].config 携带两类凭据——access 的明文
 *    apiKey/apiKeyManagementUrl 与 api.headers 的 header 型凭据（Authorization 等，
 *    provider/src/resolver.ts serializeRegistryProviderConfig 直传），响应一律
 *    strip（见 redactModelSelectionView）后才出设备。
 * 3. 本模块绝不使用 ServiceCollection.exposeOnChannelServer（全量无差别暴露，
 *    services/src/collection.ts:34-40）。
 */
import { hostname } from "node:os";
import { randomUUID } from "node:crypto";
import type { WebSocket as NodeWebSocket } from "ws";
import {
  ChannelServer,
  Emitter,
  ProxyChannel,
  SocketProtocol,
  VSBuffer,
  type ISocket,
} from "@zcode/rpc";
import {
  IBroadcastService,
  IFileService,
  IModelSelectionService,
  ISettingService,
  ITerminalService,
  IZCodeAgentService,
  IZCodeSessionService,
  IZCodeTaskService,
  createZCodeAgentConnectionScope,
  type ServiceCollection,
  type ServiceDescriptor,
} from "@zcode/services";
import {
  ZCODE_FORK_REMOTE_ENROLL_TOKEN,
  ZCODE_FORK_REMOTE_SERVER_URL,
  ZCODE_RPC_HOST_CAPABILITY_HEADER,
} from "@zcode/shared";

const CAPABILITY_FETCH_TIMEOUT_MS = 10_000;
const WS_HANDSHAKE_TIMEOUT_MS = 15_000;
const RECONNECT_BASE_DELAY_MS = 1_000;
const RECONNECT_MAX_DELAY_MS = 60_000;
/**
 * 心跳间隔。NAT 半开/对端静默死亡（睡眠无 FIN）在 TCP 层不可见，没有应用层
 * ping/pong 的连接会永远挂在 relay 注册表上（设备假在线、挂载挂死）。每tick发
 * protocol ping，上一枚 ping 未被 pong 即判定半开 → terminate → 走既有重连编排，
 * 最坏检测延迟 = 2×间隔。与 relay 侧 HOST_HEARTBEAT_INTERVAL_MS 对称，双向覆盖。
 */
const HEARTBEAT_INTERVAL_MS = 30_000;

interface RemoteBridgeLogger {
  info: (...args: unknown[]) => void;
  warn: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
}

/**
 * K2 定案的必需服务最小集（DESIGN §5-K2 + 本任务复核）：
 * - ISettingService：web bootstrap 全链（IntlProvider/useSettings/tab 恢复/providerFamilyDomain 迁移）。
 * - IModelSelectionService：composer 发送硬门禁（经 apiKey-redaction 包装，见文件头）。
 * - IZCodeAgentService：V4 会话命令通道（sendConversationCommandV4）。
 * - IZCodeSessionService / IZCodeTaskService：会话读取/状态与任务列表/元数据。
 * - IFileService / ITerminalService：文件树/附件兜底 + 终端面板（K3 硬验收项）。
 * - IBroadcastService：缺=纯降级但零风险，StoreProvider/IntlProvider 语义前提。
 * IGitService / ISystemService 未入 K2 最小集（缺=降级不挂，K2 实测），保持排除收窄审查面。
 */
export const REMOTE_BRIDGE_SERVICE_WHITELIST: readonly ServiceDescriptor<unknown>[] = [
  ISettingService,
  IModelSelectionService,
  IZCodeAgentService,
  IZCodeSessionService,
  IZCodeTaskService,
  IFileService,
  ITerminalService,
  IBroadcastService,
];

/**
 * 凭据邻接服务的 channelName 镜像清单（shared/src/channels.ts ServiceChannels）：
 * ICredentialService / IOAuthService / IProviderProvisioningTargetService / IProviderSettingsService。
 * 用字符串镜像而非 import 描述符，防止“顺手加回来”式回归；与 server/src/relay.ts
 * RELAY_FORBIDDEN_DEVICE_SERVICES 互为两侧双保险。
 */
const REMOTE_BRIDGE_FORBIDDEN_CHANNEL_NAMES: readonly string[] = [
  "credential",
  "oauth",
  "provider-provisioning-target",
  "provider-settings",
];

function assertWhitelistExcludesForbiddenServices(): void {
  const names = REMOTE_BRIDGE_SERVICE_WHITELIST.map((descriptor) => descriptor.channelName);
  for (const forbidden of REMOTE_BRIDGE_FORBIDDEN_CHANNEL_NAMES) {
    if (names.includes(forbidden)) {
      throw new Error(
        `Remote bridge whitelist must not include credential-adjacent service: ${forbidden}`,
      );
    }
  }
}

// ── apiKey redaction（K2 对 v3.1 §3 的实质修正：modelSelection 的 view 本体携带凭据）──

type UnknownRecord = Record<string, unknown>;

function isPlainObject(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * 剥离 view.providers[*].config 两处凭据面：
 * - access.{apiKey,apiKeyManagementUrl}（serializeRegistryProviderConfig 直传的明文 key）；
 * - api.headers（schema 为自由 string→string record，Authorization/x-api-key 等 header 型
 *   凭据原样出设备，K2「响应一律 strip 凭据后才出设备」同覆盖；web 侧只读 api.type/baseUrl，
 *   剥 headers 不影响远控面）。
 * 只沿需要改写的路径浅拷贝，其余引用保持原冻结对象；未知形状原样返回——
 * 结构演进时宁可放过对象，也不允许明文 key 因为 throw 被绕过整层过滤。
 */
export function redactModelSelectionView<View extends { providers?: unknown }>(view: View): View {
  if (!isPlainObject(view) || !Array.isArray(view.providers)) {
    return view;
  }
  let providersChanged = false;
  const providers = view.providers.map((provider) => {
    if (!isPlainObject(provider) || !isPlainObject(provider.config)) {
      return provider;
    }
    const config = provider.config;
    let nextConfig: UnknownRecord | null = null;
    if (isPlainObject(config.access)) {
      const access = config.access;
      if ("apiKey" in access || "apiKeyManagementUrl" in access) {
        const {
          ["apiKey"]: _apiKey,
          ["apiKeyManagementUrl"]: _apiKeyManagementUrl,
          ...restAccess
        } = access;
        nextConfig = { ...config, access: restAccess };
      }
    }
    if (isPlainObject(config.api) && "headers" in config.api) {
      const { ["headers"]: _headers, ...restApi } = config.api;
      nextConfig = { ...(nextConfig ?? config), api: restApi };
    }
    if (!nextConfig) {
      return provider;
    }
    providersChanged = true;
    return { ...provider, config: nextConfig };
  });
  return providersChanged ? { ...view, providers } : view;
}

/** IModelSelectionService 的 redaction 包装：getView 响应与 onDidChange 事件全部过滤。 */
export function createRedactedModelSelectionService(
  service: IModelSelectionService,
): IModelSelectionService {
  return {
    getView: async (input) => redactModelSelectionView(await service.getView(input)),
    onDidChange: (listener) =>
      service.onDidChange((view) => {
        listener(redactModelSelectionView(view));
      }),
  };
}

// ── ws → ISocket 适配（与 server/src/http.ts wrapWebSocket 同形，客户端方向）──

/** 设备侧心跳：ping 未被 pong → 半开，terminate 交由既有 close→reconnect 编排收口。 */
interface BridgeHeartbeat {
  stop(): void;
}

function startBridgeHeartbeat(ws: NodeWebSocket, log: RemoteBridgeLogger): BridgeHeartbeat {
  let awaitingPong = false;
  const timer = setInterval(() => {
    if (ws.readyState !== ws.OPEN) {
      return;
    }
    if (awaitingPong) {
      log.warn("[remote-bridge] heartbeat timeout (no pong); terminating half-open connection");
      try {
        ws.terminate();
      } catch {
        // 已断开；close 事件自会走重连。
      }
      return;
    }
    awaitingPong = true;
    ws.ping();
  }, HEARTBEAT_INTERVAL_MS);
  timer.unref?.();
  ws.on("pong", () => {
    awaitingPong = false;
  });
  return {
    stop() {
      clearInterval(timer);
    },
  };
}

function wrapNodeWebSocket(ws: NodeWebSocket): ISocket {
  const onData = new Emitter<VSBuffer>();
  const onClose = new Emitter<void>();
  const onEnd = new Emitter<void>();

  ws.on("message", (raw) => {
    const buf = Array.isArray(raw)
      ? Buffer.concat(raw)
      : Buffer.isBuffer(raw)
        ? raw
        : Buffer.from(raw);
    onData.fire(VSBuffer.wrap(new Uint8Array(buf)));
  });
  const handleClosed = () => {
    onClose.fire();
    onEnd.fire();
  };
  ws.on("close", handleClosed);
  ws.on("error", handleClosed);

  return {
    onData: onData.event,
    onClose: onClose.event,
    onEnd: onEnd.event,
    write(buffer: VSBuffer) {
      if (ws.readyState === ws.OPEN) {
        ws.send(buffer.buffer);
      }
    },
    end() {
      ws.close();
    },
    drain() {
      return Promise.resolve();
    },
    dispose() {
      ws.close();
    },
  };
}

// ── 连接编排 ────────────────────────────────────────────────────────────────

function toWsUrl(serverUrl: string, pathname: string, search: string): string {
  const url = new URL(serverUrl);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = `${url.pathname.replace(/\/+$/, "")}${pathname}`;
  url.search = search;
  return url.toString();
}

function computeReconnectDelayMs(attempt: number): number {
  const exponential = Math.min(
    RECONNECT_BASE_DELAY_MS * 2 ** Math.max(attempt - 1, 0),
    RECONNECT_MAX_DELAY_MS,
  );
  // full jitter：relay 重启瞬间 N 台设备不会同拍重连（防雷群，DESIGN §5-K3）。
  return Math.floor(Math.random() * exponential) + 1;
}

async function fetchHostCapability(serverUrl: string, enrollToken: string): Promise<string> {
  const endpoint = new URL("/api/rpc-host-capability", serverUrl).toString();
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { authorization: `Bearer ${enrollToken}` },
    signal: AbortSignal.timeout(CAPABILITY_FETCH_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`rpc-host-capability responded ${response.status}`);
  }
  const payload = (await response.json()) as { capability?: unknown };
  if (typeof payload.capability !== "string" || !payload.capability) {
    throw new Error("rpc-host-capability response missing capability");
  }
  return payload.capability;
}

export interface RemoteBridgeHandle {
  dispose(): Promise<void>;
}

/**
 * 启动远控桥。调用方（host/index.ts）已按构建期常量与 env 标记过滤；本函数内再挡一次
 * URL/token 缺失（双保险，行为=静默关闭）。
 */
export async function startRemoteBridge(options: {
  services: ServiceCollection;
  deviceMid?: string;
  logger: RemoteBridgeLogger;
}): Promise<RemoteBridgeHandle> {
  assertWhitelistExcludesForbiddenServices();
  const log = options.logger;
  const serverUrl = ZCODE_FORK_REMOTE_SERVER_URL;
  const enrollToken = ZCODE_FORK_REMOTE_ENROLL_TOKEN;
  if (!serverUrl || !enrollToken) {
    log.info("[remote-bridge] disabled: missing server url or enroll token");
    return { dispose: async () => {} };
  }
  // 缺设备身份必须整桥禁用（fail-closed），不能用占位身份注册：中继注册表按
  // deviceMid 单键收口，占位值会让所有无身份设备坍缩成同一个键互相 takeover 踢线。
  // main 侧经 ensureDesktopDeviceMidSync 基本总有值；真走到这里=身份读取异常，值得告警。
  const deviceMid = options.deviceMid?.trim();
  if (!deviceMid) {
    log.warn("[remote-bridge] disabled: missing device identity (deviceMid)");
    return { dispose: async () => {} };
  }
  const { WebSocket } = await import("ws");
  const host = hostname().slice(0, 256) || "unknown-host";
  const wsUrl = toWsUrl(
    serverUrl,
    "/ws/host",
    `?deviceMid=${encodeURIComponent(deviceMid)}&hostname=${encodeURIComponent(host)}`,
  );

  let disposed = false;
  let connection: BridgeConnection | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let attempt = 0;
  /** 当前连接专属的 agent connection scopes（随连接销毁）。 */
  let agentScopes: Array<{ dispose(): Promise<void> }> = [];

  const teardownConnection = async (): Promise<void> => {
    const current = connection;
    connection = null;
    const scopes = agentScopes;
    agentScopes = [];
    if (!current) {
      for (const scope of scopes) {
        try {
          await scope.dispose();
        } catch {
          // scope dispose 失败不影响收口。
        }
      }
      return;
    }
    try {
      current.heartbeat.stop();
    } catch {
      // 心跳清理失败不影响收口（terminate/close 后定时器自会空转一次后被 GC 前清掉）。
    }
    try {
      current.server.dispose();
    } catch (error) {
      log.warn("[remote-bridge] channel server dispose failed:", error);
    }
    for (const scope of scopes) {
      try {
        await scope.dispose();
      } catch {
        // 同上。
      }
    }
    try {
      current.protocol.dispose();
    } catch {
      // socket close 幂等。
    }
    current.socket.dispose();
  };

  // ── 白名单注册面（唯一，对抗审查焦点）────────────────────────────────────
  // 只注册 REMOTE_BRIDGE_SERVICE_WHITELIST；逐条 getOptional，缺失服务跳过并 warn
  // （fail-soft：少一个服务不炸整条桥，对应 K2 失败模式表的“缺=降级”）。
  const registerWhitelistedChannels = (server: ChannelServer): void => {
    for (const descriptor of REMOTE_BRIDGE_SERVICE_WHITELIST) {
      if (descriptor === IModelSelectionService) {
        const service = options.services.getOptional(IModelSelectionService);
        if (!service) {
          log.warn(`[remote-bridge] service unavailable, skip channel: ${descriptor.channelName}`);
          continue;
        }
        server.registerChannel(
          descriptor.channelName,
          ProxyChannel.fromService(createRedactedModelSelectionService(service)),
        );
        continue;
      }
      if (descriptor === IZCodeAgentService) {
        const service = options.services.getOptional(IZCodeAgentService);
        if (!service) {
          log.warn(`[remote-bridge] service unavailable, skip channel: ${descriptor.channelName}`);
          continue;
        }
        // 中继是 enroll-token 门后的 trusted host relay：连接期 facade 用
        // trusted-host-relay（身份选择在 transport 层完成，V4 hello 由下游 web 客户端
        // 经 trusted 字段透传），与 server/src/http.ts desktop-continuous 路径同构。
        const scope = createZCodeAgentConnectionScope(service, {
          connectionId: `remote-bridge-${randomUUID()}`,
          clientMode: "desktop-continuous",
          role: "trusted-host-relay",
        });
        agentScopes.push(scope);
        // V4 command 经桥落一条设备侧留痕日志：K3 E2E 用它佐证「会话确在桌面应用内
        // 执行」，也让远控触发的会话活动在设备日志里可审计（此前整条链路零输出）。
        const scopedAgentService = scope.service;
        const bridgedAgentService: IZCodeAgentService = {
          ...scopedAgentService,
          sendConversationCommandV4: async (params) => {
            log.info("[remote-bridge] sendConversationCommandV4 received from remote mount");
            return scopedAgentService.sendConversationCommandV4(params);
          },
        };
        server.registerChannel(
          descriptor.channelName,
          ProxyChannel.fromService(bridgedAgentService),
        );
        continue;
      }
      const instance = options.services.getOptional(descriptor as ServiceDescriptor<object>);
      if (!instance) {
        log.warn(`[remote-bridge] service unavailable, skip channel: ${descriptor.channelName}`);
        continue;
      }
      server.registerChannel(descriptor.channelName, ProxyChannel.fromService(instance));
    }
  };

  const scheduleReconnect = (): void => {
    if (disposed || reconnectTimer) return;
    const delayMs = computeReconnectDelayMs(attempt);
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connectOnce();
    }, delayMs);
    reconnectTimer.unref?.();
  };

  const connectOnce = (): void => {
    if (disposed) return;
    attempt += 1;
    let settledOpen = false;
    let openError: Error | null = null;

    void (async () => {
      let socket: NodeWebSocket;
      try {
        const capability = await fetchHostCapability(serverUrl, enrollToken);
        if (disposed) return;
        socket = new WebSocket(wsUrl, {
          headers: {
            [ZCODE_RPC_HOST_CAPABILITY_HEADER]: capability,
            // 网关层（Caddy）对 /ws/host 同样要求 Bearer enroll token——capability 票据
            // 只对中继有效，网关在它前面；缺这个头会在网关 401，桥表现为无限重连。
            authorization: `Bearer ${enrollToken}`,
          },
          handshakeTimeout: WS_HANDSHAKE_TIMEOUT_MS,
        });
      } catch (error) {
        if (disposed) return;
        log.warn(
          `[remote-bridge] capability fetch failed (attempt ${attempt}):`,
          error instanceof Error ? error.message : String(error),
        );
        scheduleReconnect();
        return;
      }

      socket.on("unexpected-response", (_request, response) => {
        openError = new Error(`ws upgrade rejected: ${response?.statusCode ?? "unknown"}`);
      });
      socket.on("error", (error: Error) => {
        if (!settledOpen) {
          openError = error instanceof Error ? error : new Error(String(error));
        }
      });

      socket.on("open", () => {
        if (disposed) {
          socket.close();
          return;
        }
        settledOpen = true;
        attempt = 0; // 成功建连即重置退避。
        const heartbeat = startBridgeHeartbeat(socket, log);
        const wrapped = wrapNodeWebSocket(socket);
        const protocol = new SocketProtocol(wrapped);
        const server = new ChannelServer(protocol, "remote-bridge", 1000);
        registerWhitelistedChannels(server);
        connection = { server, protocol, socket: wrapped, heartbeat };
        wrapped.onClose(() => {
          if (connection === null || disposed) {
            return;
          }
          log.info("[remote-bridge] host connection closed; scheduling reconnect");
          void teardownConnection().finally(() => {
            if (!disposed) {
              scheduleReconnect();
            }
          });
        });
        log.info(`[remote-bridge] connected to relay ${serverUrl} (deviceMid=${deviceMid})`);
      });

      socket.on("close", () => {
        if (disposed || settledOpen) {
          return;
        }
        log.warn(
          `[remote-bridge] connection failed (attempt ${attempt}):`,
          openError ? openError.message : "closed before open",
        );
        scheduleReconnect();
      });
    })();
  };

  connectOnce();

  return {
    async dispose() {
      if (disposed) {
        return;
      }
      disposed = true;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      await teardownConnection();
    },
  };
}

interface BridgeConnection {
  server: ChannelServer;
  protocol: SocketProtocol;
  socket: ISocket;
  heartbeat: BridgeHeartbeat;
}
