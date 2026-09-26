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
 * 1. `REMOTE_BRIDGE_SERVICE_WHITELIST` + `registerWhitelistedChannels` 是【唯一】注册面，
 *    且每个成员必须显式裁决为 wrapped 或 raw（`assertWhitelistExcludesForbiddenServices`
 *    启动即校验的结构化裁决，新服务入桥必须二选一并落表）：
 *    - provider-provisioning-target 永不放行（双侧硬禁）；
 *    - IOAuthService / IProviderSettingsService / IModelSelectionService /
 *      ICredentialService 是 wrapped-only：只能经 `REMOTE_BRIDGE_REDACTED_CHANNELS`
 *      的脱敏包装注册，`registerRedactedChannel` 的 brand 校验让 raw 实例注册即 fail。
 * 2. wrapped 通道的读面约束：modelSelection/provider-settings 的 view 携带两类凭据——
 *    access 的明文 apiKey/apiKeyManagementUrl 与 api.headers 的 header 型凭据
 *    （provider/src/resolver.ts serializeRegistryProviderConfig 直传），响应与
 *    onDidChange 事件一律 strip 后才出设备（redactModelSelectionView /
 *    redactProviderSettingsView）；oauth 只放观察读（登录展示态经设备侧
 *    peekCachedSessionState 无副作用合成，见 createReadOnlyOAuthService）；
 *    credential 只放键策略读（见 createReadOnlyCredentialService：active_provider/
 *    user_info 原值，token 类键只回存在性占位，其余键拒绝）。
 *    读侧直通错误一律消毒（丢 stack/passthrough 字段，见 sanitizeRemoteReadError）。
 * 3. 本模块绝不使用 ServiceCollection.exposeOnChannelServer（全量无差别暴露，
 *    services/src/collection.ts:34-40）。
 * 4. 双层信任模型（security review Major 1）：host 包装是第一道（脱敏/只读，防本设备
 *    凭据出网）；relay 对 oauth/provider-settings/credential 的方法级过滤是第二道
 *    （server/src/relay.ts RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS，防共享 enroll token
 *    的冒充主机注册 raw 服务后经原版 UI 写路径收割凭据）。两道各自独立生效。
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
  ICodingPlanSubscriptionService,
  ICredentialService,
  IFileService,
  IModelSelectionService,
  IOAuthService,
  IProviderSettingsService,
  ISettingService,
  ITerminalService,
  IUsageStatsService,
  IWindowControllerService,
  IZCodeAgentService,
  IZCodeSessionService,
  IZCodeTaskService,
  createZCodeAgentConnectionScope,
  type OffPeakClientConfig,
  type ProviderSettingsView,
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
 * K2 定案的桥上通道总清单（DESIGN §5-K2 + 本任务复核）：
 * - ISettingService：web bootstrap 全链（IntlProvider/useSettings/tab 恢复/providerFamilyDomain 迁移）。
 * - IZCodeAgentService：V4 会话命令通道（sendConversationCommandV4，raw + 连接期 scope）。
 * - IZCodeSessionService / IZCodeTaskService：会话读取/状态与任务列表/元数据。
 * - IFileService / ITerminalService：文件树/附件兜底 + 终端面板（K3 硬验收项）。
 * - IBroadcastService：缺=纯降级但零风险，StoreProvider/IntlProvider 语义前提。
 * - IModelSelectionService / IOAuthService / IProviderSettingsService / ICredentialService：
 *   wrapped-only（见下）。
 * - IWindowControllerService：raw（与 zcode-agent 同级信任——任务元数据/活动帧/置顶归档
 *   等 mutation 是用户内容面，非凭据面）。conversation 工作区任务列表走它
 *   （WorkspaceTimelineTasksSection → useGlobalTaskList），实例不来自 services 集合：
 *   每连接经 createWindowControllerService 工厂建独立 attachment（帧 emitter + 订阅
 *   随连接销毁，复用桌面窗口 exposeServicesOnMessagePort 的 createAttachmentService）。
 * - IUsageStatsService / ICodingPlanSubscriptionService：wrapped-only（用量面板/订阅读面
 *   经设备侧代取真凭据调供应商接口后只回统计；重置/支付流全拒，供应商侧读每连接
 *   限频 + 缓存击穿旗标剥离，见下方包装注释）。
 * IGitService / ISystemService 未入（缺=降级不挂，K2 实测），保持排除收窄审查面。
 * 每个成员必须落在 REMOTE_BRIDGE_REDACTED_CHANNELS（wrapped）或
 * REMOTE_BRIDGE_RAW_ALLOWED_CHANNEL_NAMES（raw）之一，否则启动即 fail——新服务入桥
 * 必须显式裁决（security review Note 6：不再依赖注册函数里的运行时特例分支）。
 */
export const REMOTE_BRIDGE_SERVICE_WHITELIST: readonly ServiceDescriptor<unknown>[] = [
  ISettingService,
  IZCodeAgentService,
  IZCodeSessionService,
  IZCodeTaskService,
  IWindowControllerService,
  IFileService,
  ITerminalService,
  IBroadcastService,
  IModelSelectionService,
  IOAuthService,
  IProviderSettingsService,
  ICredentialService,
  IUsageStatsService,
  ICodingPlanSubscriptionService,
];

/**
 * 永不放行的凭据邻接通道（双侧硬禁，任何注册形态都不允许）：
 * provider-provisioning-target。channelName 用字符串镜像（shared/src/
 * channels.ts ServiceChannels）而非 import 描述符，防止“顺手加回来”式回归；
 * 与 server/src/relay.ts RELAY_FORBIDDEN_DEVICE_SERVICES 互为两侧双保险。
 * oauth / provider-settings / credential 属于 wrapped-only：允许出现在主清单，
 * 但只能经 REMOTE_BRIDGE_REDACTED_CHANNELS 的脱敏包装注册（裁决断言 + brand
 * 校验双层强制）。
 */
const REMOTE_BRIDGE_FORBIDDEN_CHANNEL_NAMES: readonly string[] = ["provider-provisioning-target"];

/** raw 直注册显式允许清单：不在此列且非 wrapped 的主清单成员会让启动 fail。 */
const REMOTE_BRIDGE_RAW_ALLOWED_CHANNEL_NAMES: readonly string[] = [
  ISettingService.channelName,
  IZCodeAgentService.channelName,
  IZCodeSessionService.channelName,
  IZCodeTaskService.channelName,
  IWindowControllerService.channelName,
  IFileService.channelName,
  ITerminalService.channelName,
  IBroadcastService.channelName,
];

/** 单个通道名的裁决结果（assertWhitelistExcludesForbiddenServices 的结构化依据）。 */
export type RemoteBridgeChannelRuling = "wrapped" | "raw" | "forbidden" | "unruled";

/**
 * 查询通道裁决：wrapped=必须经脱敏包装注册；raw=允许直注册（显式清单）；
 * forbidden=永不放行；unruled=主清单出现该名字时启动即 fail。
 * 导出供启动断言与对抗审查测试复用。
 */
export function resolveRemoteBridgeChannelRuling(channelName: string): RemoteBridgeChannelRuling {
  if (REMOTE_BRIDGE_FORBIDDEN_CHANNEL_NAMES.includes(channelName)) {
    return "forbidden";
  }
  if (
    REMOTE_BRIDGE_REDACTED_CHANNELS.some((entry) => entry.descriptor.channelName === channelName)
  ) {
    return "wrapped";
  }
  if (REMOTE_BRIDGE_RAW_ALLOWED_CHANNEL_NAMES.includes(channelName)) {
    return "raw";
  }
  return "unruled";
}

function assertWhitelistExcludesForbiddenServices(): void {
  const names = REMOTE_BRIDGE_SERVICE_WHITELIST.map((descriptor) => descriptor.channelName);
  if (new Set(names).size !== names.length) {
    throw new Error("Remote bridge whitelist must have unique channel names");
  }
  for (const name of names) {
    const ruling = resolveRemoteBridgeChannelRuling(name);
    if (ruling === "forbidden") {
      throw new Error(
        `Remote bridge whitelist must not include credential-adjacent service: ${name}`,
      );
    }
    if (ruling === "unruled") {
      throw new Error(
        `Remote bridge channel '${name}' has no explicit wrapped/raw ruling; wrap it via REMOTE_BRIDGE_REDACTED_CHANNELS or add an explicit raw allowance`,
      );
    }
  }
  // wrapped 与 raw 二选一：同名列在两张表=两条注册路径并存，brand 强制被绕开的口子。
  for (const entry of REMOTE_BRIDGE_REDACTED_CHANNELS) {
    if (REMOTE_BRIDGE_RAW_ALLOWED_CHANNEL_NAMES.includes(entry.descriptor.channelName)) {
      throw new Error(
        `Remote bridge channel '${entry.descriptor.channelName}' is ruled both wrapped and raw`,
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
  return markRedacted<IModelSelectionService>({
    getView: async (input) => redactModelSelectionView(await service.getView(input)),
    onDidChange: (listener) =>
      service.onDidChange((view) => {
        listener(redactModelSelectionView(view));
      }),
  });
}

// ── wrapped-only 通道注册（modelSelection / oauth / provider-settings 的结构化强制）──
//
// 这些通道名不允许 raw 注册：唯一注册入口 registerRedactedChannel 校验实例带
// REMOTE_BRIDGE_REDACTED_BRAND（只有本文件的包装工厂会打标），raw 服务直接注册
// 在启动/重连注册时即 fail。原版 web UI 的 ProxyChannel 按 channel name 取服务，
// 所以通道名必须与 shared ServiceChannels 完全一致（UI 代码零改动的前提）。

const REMOTE_BRIDGE_REDACTED_BRAND = Symbol("zcode.remoteBridgeRedactedService");

function markRedacted<T extends object>(service: T): T {
  Object.defineProperty(service, REMOTE_BRIDGE_REDACTED_BRAND, {
    value: true,
    enumerable: false,
  });
  return service;
}

/** 暴露给启动断言/单测：实例是否出自本文件的脱敏包装工厂。 */
export function isRemoteBridgeRedactedService(value: unknown): boolean {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Record<symbol, unknown>)[REMOTE_BRIDGE_REDACTED_BRAND] === true
  );
}

function rejectRemoteChannelMethod(channel: string, method: string): never {
  throw new Error(`${channel}.${method} is not available on the remote bridge (read-only channel)`);
}

/**
 * 读侧直通错误消毒（security review Minor 3）：ChannelServer 会把 error.stack 与
 * code/data/detail 等 passthrough 字段全量序列化回客户端，底层错误的堆栈会携带
 * 设备路径/模块布局。这里保留 message、丢掉 stack 与全部附带字段后 rethrow；
 * 通用序列化路径（rpc/channelServer.ts）不动。
 */
function sanitizeRemoteReadError(error: unknown): never {
  const message = error instanceof Error ? error.message : String(error);
  const sanitized = new Error(message);
  sanitized.stack = undefined;
  throw sanitized;
}

/** 读侧透传 + 消毒：成功值原样返回，底层错误换成本地构造的简明 Error。 */
async function readThroughSanitized<T>(read: () => Promise<T>): Promise<T> {
  try {
    return await read();
  } catch (error) {
    sanitizeRemoteReadError(error);
  }
}

/**
 * IOAuthService 的只读观察包装（security review Major 2）。
 * 远控面 oauth 是观察视角：不做会话校验，更不触发设备端任何登录态写副作用——
 * 底层 restoreCachedSessionState/restoreSession 在 token 缺失/401/403/JWT 过期分支
 * 会 logout（clearActiveSession + 派生 provider key 删除），成功路径还有迁移写回，
 * 因此这里绝不调用它们；登录展示态经设备侧 peekCachedSessionState（纯读，解密失败
 * 按未登录处理，见 services oauthCredentialRepo.peekActiveSession）dry 合成：
 * authenticated/signed-out 两种形状，永不返回 reauthentication-required（触发它会
 * 把远端用户锁进无法在本机完成的重新认证流）。
 * 读侧返回值形状复核（shared/src/oauth.ts）：UserInfo={id,username,displayName,avatarUrl?}、
 * OAuthProviderMeta={id,displayName,enabled,order}——均无 token/secret 字段。
 * 写侧（OAuth flow/回调/轮询/刷新/登出/取消）全部抛错，抛错而不是假数据，
 * 让原版 UI 的失败分支自然生效。restoreSession 同样抛错：UI 无调用点
 * （packages/ui 全量 grep 仅 restoreCachedSessionState/getActiveProvider/getProviders）。
 */
export function createReadOnlyOAuthService(service: IOAuthService): IOAuthService {
  return markRedacted<IOAuthService>({
    getProviders: () => readThroughSanitized(() => service.getProviders()),
    getActiveProvider: () => readThroughSanitized(() => service.getActiveProvider()),
    restoreCachedSessionState: () => readThroughSanitized(() => service.peekCachedSessionState()),
    restoreCachedSession: async () => {
      const state = await readThroughSanitized(() => service.peekCachedSessionState());
      return state.status === "authenticated" ? state.userInfo : null;
    },
    restoreSession: () => rejectRemoteChannelMethod("oauth", "restoreSession"),
    peekCachedSessionState: () => rejectRemoteChannelMethod("oauth", "peekCachedSessionState"),
    startOAuth: () => rejectRemoteChannelMethod("oauth", "startOAuth"),
    startOAuthWithPolling: () => rejectRemoteChannelMethod("oauth", "startOAuthWithPolling"),
    pollPendingOAuth: () => rejectRemoteChannelMethod("oauth", "pollPendingOAuth"),
    handleCallback: () => rejectRemoteChannelMethod("oauth", "handleCallback"),
    refreshToken: () => rejectRemoteChannelMethod("oauth", "refreshToken"),
    logout: () => rejectRemoteChannelMethod("oauth", "logout"),
    logoutAll: () => rejectRemoteChannelMethod("oauth", "logoutAll"),
    cancelPending: () => rejectRemoteChannelMethod("oauth", "cancelPending"),
  });
}

/** 剥离单个 ProviderConfigObject 形状对象的两处凭据面：access.{apiKey,apiKeyManagementUrl} 与 api.headers。 */
function redactProviderConfigFields(config: UnknownRecord): UnknownRecord {
  let next: UnknownRecord | null = null;
  if (isPlainObject(config.access)) {
    const access = config.access;
    if ("apiKey" in access || "apiKeyManagementUrl" in access) {
      const {
        ["apiKey"]: _apiKey,
        ["apiKeyManagementUrl"]: _apiKeyManagementUrl,
        ...restAccess
      } = access;
      next = { ...config, access: restAccess };
    }
  }
  if (isPlainObject(config.api) && "headers" in config.api) {
    const { ["headers"]: _headers, ...restApi } = config.api;
    next = { ...(next ?? config), api: restApi };
  }
  return next ?? config;
}

/** ProviderSettingsView 内 provider 级配置出现凭据面的全部字段（models[*] 是 ModelConfigObject，不含凭据）。 */
const PROVIDER_SETTINGS_REDACTED_CONFIG_FIELDS = [
  "personalConfig",
  "effectiveConfig",
  "effectiveBuiltinConfig",
] as const;

/**
 * refresh 限频（security review Minor 5）：refresh 会触发设备上游配置源重读
 * （egress/配额消耗），web 侧不能无限循环调用。包装实例随桥连接创建/销毁，
 * 实例内窗口即“每连接”窗口。
 */
const PROVIDER_SETTINGS_REFRESH_MAX_CALLS_PER_WINDOW = 6;
const PROVIDER_SETTINGS_REFRESH_WINDOW_MS = 60_000;

/**
 * 剥离 ProviderSettingsView 的凭据面：providers[*].{personalConfig,effectiveConfig,
 * effectiveBuiltinConfig} 与 providerTemplates[*].config（均为 ProviderConfigObject）。
 * 手法与 redactModelSelectionView 一致：只沿需要改写的路径浅拷贝，未知形状原样放过；
 * accountState（AccountProviderState）已复核只含 availability/entitled/connectionKey 等
 * 非凭据字段（provider/src/account-provider-state.ts 自述“不包含凭据”），不剥。
 * 已知残留面（security review Minor 4，文档化不剥）：api.baseUrl 理论上可内嵌
 * query 形式的 key（如 ?api-key=…），但按字段名剥除会误伤全部合法 URL——与
 * redactModelSelectionView 对 modelSelection 的取舍一致，接受该残留。
 */
export function redactProviderSettingsView<
  View extends { providers?: unknown; providerTemplates?: unknown },
>(view: View): View {
  if (!isPlainObject(view)) {
    return view;
  }
  let changed = false;
  let providers: unknown[] | undefined;
  if (Array.isArray(view.providers)) {
    providers = view.providers.map((provider) => {
      if (!isPlainObject(provider)) {
        return provider;
      }
      let nextProvider: UnknownRecord | null = null;
      for (const field of PROVIDER_SETTINGS_REDACTED_CONFIG_FIELDS) {
        const config = provider[field];
        if (!isPlainObject(config)) {
          continue;
        }
        const redactedConfig = redactProviderConfigFields(config);
        if (redactedConfig !== config) {
          nextProvider = { ...(nextProvider ?? provider), [field]: redactedConfig };
        }
      }
      if (!nextProvider) {
        return provider;
      }
      changed = true;
      return nextProvider;
    });
  }
  let providerTemplates: unknown[] | undefined;
  if (Array.isArray(view.providerTemplates)) {
    providerTemplates = view.providerTemplates.map((template) => {
      if (!isPlainObject(template) || !isPlainObject(template.config)) {
        return template;
      }
      const redactedConfig = redactProviderConfigFields(template.config);
      if (redactedConfig === template.config) {
        return template;
      }
      changed = true;
      return { ...template, config: redactedConfig };
    });
  }
  if (!changed) {
    return view;
  }
  return {
    ...view,
    ...(providers ? { providers } : {}),
    ...(providerTemplates ? { providerTemplates } : {}),
  };
}

/**
 * IProviderSettingsService 的只读脱敏包装：getView/refresh 响应与 onDidChange 事件
 * 全部过滤，读侧直通错误消毒（丢设备堆栈）；refresh 有限频（见下方常量），超限回放
 * 最近一次成功 view 而不是报错——原版 UI 的刷新流是读侧自动重试语义，报错会炸
 * toast，回放的是设备已认可的真实快照（脱敏后），不构成假数据；连一次成功快照都
 * 还没有时才抛明确错误。全部 mutation（含 resolveModelConfig/testModelConnectivity
 * 这类编辑器辅助流）一律抛错——远控面是只读观察，不是第二套配置编辑入口。
 */
export function createRedactedProviderSettingsService(
  service: IProviderSettingsService,
): IProviderSettingsService {
  let refreshCallTimestamps: number[] = [];
  let lastRedactedView: ProviderSettingsView | null = null;
  const getView = async (): Promise<ProviderSettingsView> => {
    const view = redactProviderSettingsView(await readThroughSanitized(() => service.getView()));
    lastRedactedView = view;
    return view;
  };
  const refresh = async (reason: string): Promise<ProviderSettingsView> => {
    const now = Date.now();
    refreshCallTimestamps = refreshCallTimestamps.filter(
      (timestamp) => now - timestamp < PROVIDER_SETTINGS_REFRESH_WINDOW_MS,
    );
    if (refreshCallTimestamps.length >= PROVIDER_SETTINGS_REFRESH_MAX_CALLS_PER_WINDOW) {
      if (lastRedactedView) {
        return lastRedactedView;
      }
      throw new Error(
        "provider-settings.refresh is rate limited on the remote bridge; retry later",
      );
    }
    refreshCallTimestamps.push(now);
    const view = redactProviderSettingsView(
      await readThroughSanitized(() => service.refresh(reason)),
    );
    lastRedactedView = view;
    return view;
  };
  return markRedacted<IProviderSettingsService>({
    getView,
    refresh,
    onDidChange: (listener) =>
      service.onDidChange((view) => {
        listener(redactProviderSettingsView(view));
      }),
    createPersonalProvider: () =>
      rejectRemoteChannelMethod("provider-settings", "createPersonalProvider"),
    resolveModelConfig: () => rejectRemoteChannelMethod("provider-settings", "resolveModelConfig"),
    savePersonalProviderOverlay: () =>
      rejectRemoteChannelMethod("provider-settings", "savePersonalProviderOverlay"),
    deletePersonalProvider: () =>
      rejectRemoteChannelMethod("provider-settings", "deletePersonalProvider"),
    reorderPersonalProviders: () =>
      rejectRemoteChannelMethod("provider-settings", "reorderPersonalProviders"),
    reorderPersonalModels: () =>
      rejectRemoteChannelMethod("provider-settings", "reorderPersonalModels"),
    addPersonalModel: () => rejectRemoteChannelMethod("provider-settings", "addPersonalModel"),
    renamePersonalModel: () =>
      rejectRemoteChannelMethod("provider-settings", "renamePersonalModel"),
    deletePersonalModel: () =>
      rejectRemoteChannelMethod("provider-settings", "deletePersonalModel"),
    savePersonalModelDraft: () =>
      rejectRemoteChannelMethod("provider-settings", "savePersonalModelDraft"),
    setPersonalModelEnabled: () =>
      rejectRemoteChannelMethod("provider-settings", "setPersonalModelEnabled"),
    testModelConnectivity: () =>
      rejectRemoteChannelMethod("provider-settings", "testModelConnectivity"),
  });
}

// ── credential：键策略只读（E2E 第三缺口：原版设置页打开时的 3 条 credential.load）──

/** presence 键的真值替代串：真值非空时回此占位，真 token 绝不出设备。 */
export const REMOTE_BRIDGE_CREDENTIAL_PRESENT_PLACEHOLDER = "redacted-present";

/**
 * token 类键（值本身即机密）：oauth 派生 token 按 services/src/oauth/repo/
 * oauthCredentialRepo 的 key 形状 + purchase_token 预留段；zcodejwttoken 是
 * 官网购买页通用 JWT（packages/ui getCodingPlanCredentialKeys）。只回存在性占位。
 */
const REMOTE_BRIDGE_CREDENTIAL_TOKEN_KEY_PATTERN =
  /^oauth:[a-z0-9-]+:(access_token|refresh_token|id_token|purchase_token)$/;
/** 展示载荷键：user_info 是登录展示 profile（oauth 通道 peek 已在服务等价信息）。 */
const REMOTE_BRIDGE_CREDENTIAL_USER_INFO_KEY_PATTERN = /^oauth:[a-z0-9-]+:user_info$/;

/**
 * credential.load 的逐键裁决（deny-first，导出供表驱动断言/单测）：
 * - "passthrough"：原值返回——active_provider 是 provider id 选择器、user_info 是
 *   展示载荷，均非机密；
 * - "presence"：真值非空→固定占位串、空/null→null——packages/ui 的 token 消费方
 *   全部只做 `.trim().length > 0` 存在性判断或稳定等值比较（见调用点表格，
 *   ModelProviderSection/useCodingPlanEntryPlanList/CodingPlanEmbeddedWebviewDialog），
 *   占位串对它们语义等价；
 * - null：其余键（bot:、web-remote-control:、account-provider:、remote-workspace:、
 *   legacy auth_token 等一切）拒绝——deny-first，白名单外的键不允许经桥探测/读取。
 */
export type RemoteBridgeCredentialKeyRuling = "passthrough" | "presence";

export function resolveRemoteBridgeCredentialKeyRuling(
  key: string,
): RemoteBridgeCredentialKeyRuling | null {
  if (key === "oauth:active_provider" || REMOTE_BRIDGE_CREDENTIAL_USER_INFO_KEY_PATTERN.test(key)) {
    return "passthrough";
  }
  if (key === "zcodejwttoken" || REMOTE_BRIDGE_CREDENTIAL_TOKEN_KEY_PATTERN.test(key)) {
    return "presence";
  }
  return null;
}

/**
 * ICredentialService 的键策略只读包装（通道名 "credential"，原版 UI 零改动取用）。
 * load 先裁键再触底（deny-first：白名单外的键在设备侧就拒绝，不构成存在性预言机）；
 * token 类键绝不返回真值；save/delete 全部抛错——写面只剩 reject，配合 relay 侧
 * credential:["load"] 方法墙构成双道防线。读侧直通错误消毒同其它 wrapped 通道。
 */
export function createReadOnlyCredentialService(service: ICredentialService): ICredentialService {
  return markRedacted<ICredentialService>({
    load: async (key) => {
      const ruling = resolveRemoteBridgeCredentialKeyRuling(key);
      if (!ruling) {
        throw new Error(
          `credential.load key '${key}' is not available on the remote bridge (read-only key policy)`,
        );
      }
      const value = await readThroughSanitized(() => service.load(key));
      if (ruling === "passthrough") {
        return value;
      }
      return value !== null && value.trim().length > 0
        ? REMOTE_BRIDGE_CREDENTIAL_PRESENT_PLACEHOLDER
        : null;
    },
    save: () => rejectRemoteChannelMethod("credential", "save"),
    delete: () => rejectRemoteChannelMethod("credential", "delete"),
  });
}

// ── 供应商侧读限频 + 缓存击穿旗标剥离（security review minor）────────────────

/**
 * 供应商侧读限频窗口（照 createRedactedProviderSettingsService 的 refresh 先例
 * 6 次/60s 滑动窗口）：usage-stats 5 个放行读与 coding-plan-subscription 的
 * 供应商侧读子集（preview/pricing/balance/orders/client-configs 等）会把网页调用
 * 放大成设备 egress 与供应商配额消耗——getEntitlementSnapshot 单次还能扇出 1-3 个
 * 供应商请求。包装实例随桥连接创建/销毁，实例内窗口即"每连接"窗口。
 */
const VENDOR_READ_MAX_CALLS_PER_WINDOW = 6;
const VENDOR_READ_WINDOW_MS = 60_000;

/**
 * 每连接限频读注册表：按方法键各设一个滑动窗口；超限回放最近一次成功值
 * （refresh 同款语义——原版 UI 的读侧自动重试不该因限频炸 toast，回放的是设备
 * 已认可的真实响应），连一次成功值都还没有时才抛明确错误。回放缓存存的是包装层
 * 返回值（已脱敏），重放不会把凭据面带回。
 */
function createRateLimitedReads(): {
  read<T>(key: string, read: () => Promise<T>): Promise<T>;
} {
  const callTimestampsByKey = new Map<string, number[]>();
  const lastValueByKey = new Map<string, unknown>();
  return {
    async read<T>(key: string, read: () => Promise<T>): Promise<T> {
      const now = Date.now();
      const timestamps = (callTimestampsByKey.get(key) ?? []).filter(
        (timestamp) => now - timestamp < VENDOR_READ_WINDOW_MS,
      );
      if (timestamps.length >= VENDOR_READ_MAX_CALLS_PER_WINDOW) {
        if (lastValueByKey.has(key)) {
          return lastValueByKey.get(key) as T;
        }
        throw new Error(`${key} is rate limited on the remote bridge; retry later`);
      }
      timestamps.push(now);
      callTimestampsByKey.set(key, timestamps);
      const value = await readThroughSanitized(read);
      lastValueByKey.set(key, value);
      return value;
    },
  };
}

/**
 * 请求旗标剥离：远控面没有主动击穿缓存的合法场景——invalidateBalanceCache
 * （usage entitlement，使 Start Plan balance 短期缓存失效）与 forceRefresh
 * （subscription client/configs 快照，跳过 1h 缓存）只会放大设备 egress，
 * 一律剥掉后转发；无旗标（或为 false）的请求原引用直通。
 */
function stripRequestFlag<Request extends object>(
  request: Request | undefined,
  flag: keyof Request & string,
): Request | undefined {
  if (!request || request[flag] !== true) {
    return request;
  }
  const { [flag]: _strippedFlag, ...rest } = request as Record<string, unknown>;
  return rest as Request;
}

// ── usage-stats：用量只读（设备侧代取：真凭据只在设备侧用于调供应商统计接口）──

/**
 * IUsageStatsService 的只读包装。放行 5 个读：getAppUsageSnapshot / getCodingPlanUsageSnapshot
 * / getCodingPlanResetStatus / getSnapshot / getEntitlementSnapshot。响应字段审计
 * （shared/src/usage-stats.ts + usage-quota.ts + coding-plan-reset.ts）：全部是用量数字、
 * 日期、model/tool 代号、quota 桶（planId/usage/remaining/nextResetTime）与
 * subscription.identityMasked（按设计即脱敏的账号标识）——无 token/key/secret 样字段，
 * 不需要逐字段剥除。请求侧 accountAccess（zcodeAccountAccessSchema）只携带 plan 上下文
 * 标识（family/planKind/productId/organizationId），凭据解析完全发生在设备侧——这正是
 * 「设备侧代取」模式：网页只需要统计结果，永远不需要真 key。
 * 拒绝 3 个：useCodingPlanReset / requestCodingPlanResetOpportunity（供应商侧重置动作，
 * 远控不做）/ markCodingPlanResetHistoryRead（写已读状态）。抛错而不是假数据，原版 UI
 * 的失败分支自然生效（重置入口远端不可用是文档化取舍）。
 * 全部 5 读走每连接限频窗口（见 createRateLimitedReads）；getEntitlementSnapshot
 * 请求里的 invalidateBalanceCache 旗标剥离（远控面没有主动击穿缓存的场景）。
 */
export function createReadOnlyUsageStatsService(service: IUsageStatsService): IUsageStatsService {
  const vendorReads = createRateLimitedReads();
  return markRedacted<IUsageStatsService>({
    getAppUsageSnapshot: (request) =>
      vendorReads.read("usage-stats.getAppUsageSnapshot", () =>
        service.getAppUsageSnapshot(request),
      ),
    getCodingPlanUsageSnapshot: (request) =>
      vendorReads.read("usage-stats.getCodingPlanUsageSnapshot", () =>
        service.getCodingPlanUsageSnapshot(request),
      ),
    getCodingPlanResetStatus: (request) =>
      vendorReads.read("usage-stats.getCodingPlanResetStatus", () =>
        service.getCodingPlanResetStatus(request),
      ),
    getSnapshot: (request) =>
      vendorReads.read("usage-stats.getSnapshot", () => service.getSnapshot(request)),
    getEntitlementSnapshot: (request) =>
      vendorReads.read("usage-stats.getEntitlementSnapshot", () =>
        service.getEntitlementSnapshot(stripRequestFlag(request, "invalidateBalanceCache")),
      ),
    requestCodingPlanResetOpportunity: () =>
      rejectRemoteChannelMethod("usage-stats", "requestCodingPlanResetOpportunity"),
    useCodingPlanReset: () => rejectRemoteChannelMethod("usage-stats", "useCodingPlanReset"),
    markCodingPlanResetHistoryRead: () =>
      rejectRemoteChannelMethod("usage-stats", "markCodingPlanResetHistoryRead"),
  });
}

// ── coding-plan-subscription：订阅读面 + 支付流全拒 ──────────────────────────

/**
 * 剥离 getOffPeakClientConfig 响应内嵌的 ModelSelectionView 凭据面：与 modelSelection
 * 通道同一口径（redactModelSelectionView），off-peak 只需要入口曝光开关与模型展示，
 * 剥 access.{apiKey,apiKeyManagementUrl} 与 api.headers 不影响远控面。
 */
export function redactOffPeakClientConfig(config: OffPeakClientConfig): OffPeakClientConfig {
  const redactedView = redactModelSelectionView(config.modelSelectionView);
  return redactedView === config.modelSelectionView
    ? config
    : { ...config, modelSelectionView: redactedView };
}

/**
 * ICodingPlanSubscriptionService 的只读包装（逐方法裁决，全接口 29 成员）。
 * 放行读 15：batchPreview / getStaticProducts / getStaticTeamProducts /
 * getStartPlanPreview / getOffPeakClientConfig（响应内嵌 modelSelectionView，剥凭据后放行）
 * / getDynamicWorkflowClientConfig / getModelContextBudgetStrategy / getForceUpdateConfig
 * / productInfo / preview / getEnterprisePricing / getEnterpriseBalance /
 * calculateEnterpriseOrder / getEnterprisePendingOrders / checkEnterpriseOrderStatus——
 * 均为产品目录/定价/余额/订单状态读（calculateEnterpriseOrder 是纯价格试算，不落单），
 * 响应类型审计无凭据样字段（Stripe 卡面 paymentMethodId/last4 属 queryStripeCards，
 * 在拒绝侧）。拒绝 14：createSign / updateSign / checkPayment / checkPendingOrders /
 * queryStripeCards / bindStripeCard / unbindStripeCard / payStripe / checkPaypalSupport
 * / createPaypalSetupToken / subscribePaypal / createEnterpriseOrder / cancelEnterpriseOrder
 * / continueEnterpriseOrderPayment——支付流（签约/绑卡/扣款/下单/续付）远端明确不做，
 * 抛错让原版 UI 的失败分支自然生效。
 * 14 个供应商侧读（除 getModelContextBudgetStrategy——固定常量不打网络）走每连接
 * 限频窗口；getOffPeakClientConfig / getDynamicWorkflowClientConfig 请求里的
 * forceRefresh 旗标剥离（client/configs 有 1h 快照缓存，远控面没有击穿缓存的场景）。
 */
export function createReadOnlyCodingPlanSubscriptionService(
  service: ICodingPlanSubscriptionService,
): ICodingPlanSubscriptionService {
  const vendorReads = createRateLimitedReads();
  const throttled = <T>(method: string, read: () => Promise<T>): Promise<T> =>
    vendorReads.read(`coding-plan-subscription.${method}`, read);
  return markRedacted<ICodingPlanSubscriptionService>({
    batchPreview: (request) => throttled("batchPreview", () => service.batchPreview(request)),
    getStaticProducts: () => throttled("getStaticProducts", () => service.getStaticProducts()),
    getStaticTeamProducts: () =>
      throttled("getStaticTeamProducts", () => service.getStaticTeamProducts()),
    getStartPlanPreview: () =>
      throttled("getStartPlanPreview", () => service.getStartPlanPreview()),
    getOffPeakClientConfig: (options) =>
      throttled("getOffPeakClientConfig", async () =>
        redactOffPeakClientConfig(
          await service.getOffPeakClientConfig(stripRequestFlag(options, "forceRefresh")),
        ),
      ),
    getDynamicWorkflowClientConfig: (options) =>
      throttled("getDynamicWorkflowClientConfig", () =>
        service.getDynamicWorkflowClientConfig(stripRequestFlag(options, "forceRefresh")),
      ),
    getModelContextBudgetStrategy: () =>
      readThroughSanitized(() => service.getModelContextBudgetStrategy()),
    getForceUpdateConfig: () =>
      throttled("getForceUpdateConfig", () => service.getForceUpdateConfig()),
    productInfo: (request) => throttled("productInfo", () => service.productInfo(request)),
    preview: (request) => throttled("preview", () => service.preview(request)),
    getEnterprisePricing: (request) =>
      throttled("getEnterprisePricing", () => service.getEnterprisePricing(request)),
    getEnterpriseBalance: () =>
      throttled("getEnterpriseBalance", () => service.getEnterpriseBalance()),
    calculateEnterpriseOrder: (request) =>
      throttled("calculateEnterpriseOrder", () => service.calculateEnterpriseOrder(request)),
    getEnterprisePendingOrders: () =>
      throttled("getEnterprisePendingOrders", () => service.getEnterprisePendingOrders()),
    checkEnterpriseOrderStatus: (request) =>
      throttled("checkEnterpriseOrderStatus", () => service.checkEnterpriseOrderStatus(request)),
    createSign: () => rejectRemoteChannelMethod("coding-plan-subscription", "createSign"),
    updateSign: () => rejectRemoteChannelMethod("coding-plan-subscription", "updateSign"),
    checkPayment: () => rejectRemoteChannelMethod("coding-plan-subscription", "checkPayment"),
    checkPendingOrders: () =>
      rejectRemoteChannelMethod("coding-plan-subscription", "checkPendingOrders"),
    queryStripeCards: () =>
      rejectRemoteChannelMethod("coding-plan-subscription", "queryStripeCards"),
    bindStripeCard: () => rejectRemoteChannelMethod("coding-plan-subscription", "bindStripeCard"),
    unbindStripeCard: () =>
      rejectRemoteChannelMethod("coding-plan-subscription", "unbindStripeCard"),
    payStripe: () => rejectRemoteChannelMethod("coding-plan-subscription", "payStripe"),
    checkPaypalSupport: () =>
      rejectRemoteChannelMethod("coding-plan-subscription", "checkPaypalSupport"),
    createPaypalSetupToken: () =>
      rejectRemoteChannelMethod("coding-plan-subscription", "createPaypalSetupToken"),
    subscribePaypal: () =>
      rejectRemoteChannelMethod("coding-plan-subscription", "subscribePaypal"),
    createEnterpriseOrder: () =>
      rejectRemoteChannelMethod("coding-plan-subscription", "createEnterpriseOrder"),
    cancelEnterpriseOrder: () =>
      rejectRemoteChannelMethod("coding-plan-subscription", "cancelEnterpriseOrder"),
    continueEnterpriseOrderPayment: () =>
      rejectRemoteChannelMethod("coding-plan-subscription", "continueEnterpriseOrderPayment"),
  });
}

/** wrapped-only 通道注册表：descriptor 只用来取实例与 channel 名，包装工厂是唯一产物来源。 */
interface RemoteBridgeRedactedChannelRegistration {
  readonly descriptor: ServiceDescriptor<object>;
  readonly createWrapped: (service: object) => object;
}

/** 收窄定义点，让循环注册侧拿到统一的非泛型形状（cast 只发生在这里）。 */
function defineRedactedChannel<T>(
  descriptor: ServiceDescriptor<T>,
  createWrapped: (service: T) => T,
): RemoteBridgeRedactedChannelRegistration {
  return {
    descriptor: descriptor as ServiceDescriptor<object>,
    createWrapped: createWrapped as unknown as (service: object) => object,
  };
}

/**
 * wrapped-only 通道注册表（原版 web UI 按 channel name 消费这些通道）。
 * 每条 = 描述符 + 脱敏/只读包装工厂；raw 实例没有入口（见文件头安全边界第 1 条）。
 */
const REMOTE_BRIDGE_REDACTED_CHANNELS: readonly RemoteBridgeRedactedChannelRegistration[] = [
  defineRedactedChannel(IModelSelectionService, createRedactedModelSelectionService),
  defineRedactedChannel(IOAuthService, createReadOnlyOAuthService),
  defineRedactedChannel(IProviderSettingsService, createRedactedProviderSettingsService),
  defineRedactedChannel(ICredentialService, createReadOnlyCredentialService),
  defineRedactedChannel(IUsageStatsService, createReadOnlyUsageStatsService),
  defineRedactedChannel(ICodingPlanSubscriptionService, createReadOnlyCodingPlanSubscriptionService),
];

/**
 * wrapped-only 通道的唯一 registerChannel 入口：实例必须带包装 brand（只有本文件的
 * 脱敏工厂会打标）。raw IOAuthService/IProviderSettingsService/ICredentialService
 * 流入这里会在注册时立即 throw——桥按连接注册，等价于启动即 fail。
 */
export function registerRedactedChannel(
  server: ChannelServer,
  channelName: string,
  wrappedService: object,
): void {
  if (!isRemoteBridgeRedactedService(wrappedService)) {
    throw new Error(
      `Remote bridge channel '${channelName}' must be registered through its redaction wrapper (raw service rejected)`,
    );
  }
  server.registerChannel(channelName, ProxyChannel.fromService(wrappedService));
}

/**
 * raw 直注册的唯一入口：通道名必须在 REMOTE_BRIDGE_RAW_ALLOWED_CHANNEL_NAMES 显式
 * 清单内，否则注册即 throw。与 registerRedactedChannel 对称——wrapped/raw 两条注册
 * 路径各自有入口级强制，绕过任何一张裁决表都会在这里暴露。
 */
function registerRawChannel(server: ChannelServer, channelName: string, instance: object): void {
  if (!REMOTE_BRIDGE_RAW_ALLOWED_CHANNEL_NAMES.includes(channelName)) {
    throw new Error(
      `Remote bridge channel '${channelName}' has no explicit raw allowance; register it via a redaction wrapper or extend the raw allowance list`,
    );
  }
  server.registerChannel(channelName, ProxyChannel.fromService(instance));
}

/**
 * window-controller attachment 的 RPC 面裁剪：dispose 是设备侧生命周期钩子（随桥连接
 * 销毁），不属于远端可调用的成员——留在面上等于让任一网页客户端一条 dispose 调用拆掉
 * 本连接的任务列表订阅。剥离后经 raw 入口注册，其余 8 个接口成员全放行
 * （deleteArchivedTask 与 deleteArchivedTasks 是两个独立方法）。
 */
export function createWindowControllerRpcSurface(
  attachment: IWindowControllerService & { dispose(): void },
): IWindowControllerService {
  const { ["dispose"]: _dispose, ...rpcSurface } = attachment;
  return rpcSurface;
}

/**
 * 桥连接的每连接资源簿：registerWhitelistedChannels 在连接注册期填充（agent
 * connection scope / window-controller attachment），teardownConnection 的
 * 有/无 current connection 两个分支统一经 disposeAll 收口——attachment 的帧
 * emitter 与 Controller 订阅随连接销毁，不泄漏进下一条连接。disposeAll 清空
 * 簿本后返回，重复调用幂等；单个成员 dispose 抛错不阻塞其余成员收口。
 * 导出供生命周期单测直接驱动两个分支形态（security review note）。
 */
export function createRemoteBridgeConnectionResources() {
  const agentScopes: Array<{ dispose(): Promise<void> }> = [];
  const windowControllerAttachments: Array<{ dispose(): void }> = [];
  return {
    agentScopes,
    windowControllerAttachments,
    async disposeAll(): Promise<void> {
      const scopes = agentScopes.splice(0, agentScopes.length);
      for (const scope of scopes) {
        try {
          await scope.dispose();
        } catch {
          // scope dispose 失败不影响收口。
        }
      }
      const attachments = windowControllerAttachments.splice(
        0,
        windowControllerAttachments.length,
      );
      for (const attachment of attachments) {
        try {
          attachment.dispose();
        } catch {
          // attachment dispose 失败不影响收口。
        }
      }
    },
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
  /**
   * window-controller 的每连接实例工厂：传 windowHostControllerRuntime.createAttachmentService
   * （帧 emitter + Controller 订阅随返回实例 dispose 销毁）。每次调用必须返回全新实例——
   * 桥按连接注册/销毁，实例复用会让上一条连接的订阅泄漏进下一条。缺失时该通道跳过
   * （fail-soft，与其余缺服务同语义）。
   */
  createWindowControllerService?: () => IWindowControllerService & { dispose(): void };
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
  /** 当前连接专属资源（agent scopes + window-controller attachments），随连接销毁。 */
  const connectionResources = createRemoteBridgeConnectionResources();

  const teardownConnection = async (): Promise<void> => {
    const current = connection;
    connection = null;
    // 有/无 current connection 两分支共用同一收口：attachments/scopes 永远随
    // teardown 释放（见 createRemoteBridgeConnectionResources）。
    if (!current) {
      await connectionResources.disposeAll();
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
    await connectionResources.disposeAll();
    try {
      current.protocol.dispose();
    } catch {
      // socket close 幂等。
    }
    current.socket.dispose();
  };

  // ── 白名单注册面（唯一，对抗审查焦点）────────────────────────────────────
  // 逐条 getOptional，缺失服务跳过并 warn（fail-soft：少一个服务不炸整条桥，
  // 对应 K2 失败模式表的“缺=降级”）。wrapped/raw 裁决由启动断言保证与
  // REMOTE_BRIDGE_SERVICE_WHITELIST 一致；这里按裁决分派，不存在未裁决分支。
  const registerWhitelistedChannels = (server: ChannelServer): void => {
    const wrappedFactoryByChannelName = new Map(
      REMOTE_BRIDGE_REDACTED_CHANNELS.map((entry) => [
        entry.descriptor.channelName,
        entry.createWrapped,
      ]),
    );
    for (const descriptor of REMOTE_BRIDGE_SERVICE_WHITELIST) {
      // window-controller：raw 裁决成员的连接期编排特例（非脱敏包装）。实例不来自
      // services 集合——每连接经工厂建独立 attachment（帧 emitter + Controller 订阅），
      // 挂进 connectionResources 随连接销毁；RPC 面经
      // createWindowControllerRpcSurface 剥离设备侧 dispose 钩子后注册。
      if (descriptor === IWindowControllerService) {
        const createAttachment = options.createWindowControllerService;
        if (!createAttachment) {
          log.warn(`[remote-bridge] service unavailable, skip channel: ${descriptor.channelName}`);
          continue;
        }
        const attachment = createAttachment();
        connectionResources.windowControllerAttachments.push(attachment);
        registerRawChannel(
          server,
          descriptor.channelName,
          createWindowControllerRpcSurface(attachment),
        );
        continue;
      }
      const instance = options.services.getOptional(descriptor as ServiceDescriptor<object>);
      if (!instance) {
        log.warn(`[remote-bridge] service unavailable, skip channel: ${descriptor.channelName}`);
        continue;
      }
      const createWrapped = wrappedFactoryByChannelName.get(descriptor.channelName);
      if (createWrapped) {
        registerRedactedChannel(server, descriptor.channelName, createWrapped(instance));
        continue;
      }
      if (descriptor === IZCodeAgentService) {
        // 中继是 enroll-token 门后的 trusted host relay：连接期 facade 用
        // trusted-host-relay（身份选择在 transport 层完成，V4 hello 由下游 web 客户端
        // 经 trusted 字段透传），与 server/src/http.ts desktop-continuous 路径同构。
        // （raw 裁决成员的连接期编排特例，非脱敏包装。）
        const scope = createZCodeAgentConnectionScope(instance as IZCodeAgentService, {
          connectionId: `remote-bridge-${randomUUID()}`,
          clientMode: "desktop-continuous",
          role: "trusted-host-relay",
        });
        connectionResources.agentScopes.push(scope);
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
      registerRawChannel(server, descriptor.channelName, instance);
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
