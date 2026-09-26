import type { ZCodeRuntimeEnv } from "./runtimeEnv.js";

export type ZCodeEnv = "test" | "production";
/** 安装包身份：决定应用名、app id、Electron 数据目录与更新策略；与后端环境 `ZCodeEnv` 是两个轴。 */
export type ZCodeProductFlavor = "production" | "preview";
export type ArmsRumEnv = "local" | "prod";

// 非构建环境（如 e2e 测试的 mocha）下 define 不存在，用 typeof 检查 + fallback 避免 ReferenceError
declare const __ZCODE_ENV__: string;
declare const __ZCODE_PRODUCT_FLAVOR__: string;
declare const __ZCODE_FORK_UPDATE_FEED_URL__: string;
declare const __ZCODE_FORK_UPDATE_FEED_TOKEN__: string;
declare const __ZCODE_FORK_REMOTE_SERVER_URL__: string;
declare const __ZCODE_FORK_REMOTE_ENROLL_TOKEN__: string;

export function normalizeZCodeEnv(value: string | undefined): ZCodeEnv {
  return value?.trim().toLowerCase() === "production" ? "production" : "test";
}

export const ZCODE_ENV = normalizeZCodeEnv(
  typeof __ZCODE_ENV__ !== "undefined" ? __ZCODE_ENV__ : undefined,
);

/**
 * 身份缺省跟随后端环境（test → preview，production → production）。
 * 桌面构建通过 `ZCODE_PREVIEW_IDENTITY=1` 显式注入 preview，得到连接生产后端的 Preview 包；
 * 未注入 define 的 bundle（web、CLI、测试）沿用旧的单轴语义。
 */
export function normalizeZCodeProductFlavor(
  value: string | undefined,
  zcodeEnv: ZCodeEnv,
): ZCodeProductFlavor {
  const normalized = value?.trim().toLowerCase();
  if (normalized === "production" || normalized === "preview") {
    return normalized;
  }
  return zcodeEnv === "production" ? "production" : "preview";
}

export const ZCODE_PRODUCT_FLAVOR = normalizeZCodeProductFlavor(
  typeof __ZCODE_PRODUCT_FLAVOR__ !== "undefined" ? __ZCODE_PRODUCT_FLAVOR__ : undefined,
  ZCODE_ENV,
);

/**
 * Fork 决策（LanicBlue/ZCode）：更新链路默认关闭；构建期通过
 * `ZCODE_FORK_UPDATE_FEED_URL` 注入自托管 feed（指向一个静态目录的 manifest YAML，
 * 同目录放置 zip+blockmap）后整条链路重新打开，指向自有源——版本检测、手动下载、
 * 重启安装都走自己的服务器，官方 CDN 不再参与。
 */
export const ZCODE_FORK_UPDATE_FEED_URL: string =
  typeof __ZCODE_FORK_UPDATE_FEED_URL__ !== "undefined" ? __ZCODE_FORK_UPDATE_FEED_URL__ : "";

/**
 * 自托管 feed 的 Bearer token（构建期 `ZCODE_FORK_UPDATE_FEED_TOKEN` 注入）。
 * feed 挂在自有服务器上时配合网关层 Authorization 头校验；随 manifest 与
 * zip/blockmap 下载一并携带。只进自己的私有构建产物，不进仓库。
 */
export const ZCODE_FORK_UPDATE_FEED_TOKEN: string =
  typeof __ZCODE_FORK_UPDATE_FEED_TOKEN__ !== "undefined" ? __ZCODE_FORK_UPDATE_FEED_TOKEN__ : "";

/** 更新入口总门：无自托管 feed 时维持全关（与最初 fork 决策一致）。 */
export const ZCODE_FORK_DISABLE_UPDATES: boolean = ZCODE_FORK_UPDATE_FEED_URL === "";

/**
 * Fork 远控桥（zcode-web-selfhost DESIGN v3.1 §5-K3）：ECS 中继地址（如
 * https://zcode.codenotincluded.com）。构建期 `ZCODE_FORK_REMOTE_SERVER_URL` 注入；
 * 空 = 桥模块整体静默关闭（行为同无 feed 时更新链全关），不出网、不 spawn 专用 host。
 */
export const ZCODE_FORK_REMOTE_SERVER_URL: string =
  typeof __ZCODE_FORK_REMOTE_SERVER_URL__ !== "undefined" ? __ZCODE_FORK_REMOTE_SERVER_URL__ : "";

/**
 * 中继的设备准入凭据（构建期 `ZCODE_FORK_REMOTE_ENROLL_TOKEN` 注入）：Bearer enroll token，
 * 只用于桌面→中继方向（POST /api/rpc-host-capability + /ws/host 握手前的取票）。
 * 与 `ZCODE_FORK_UPDATE_FEED_TOKEN` 绝不复用（泄漏面合并=能拉安装包即可注册设备，DESIGN §7）。
 */
export const ZCODE_FORK_REMOTE_ENROLL_TOKEN: string =
  typeof __ZCODE_FORK_REMOTE_ENROLL_TOKEN__ !== "undefined"
    ? __ZCODE_FORK_REMOTE_ENROLL_TOKEN__
    : "";

/** 桥总门：URL 为空即整模块关闭（token 缺失时同样关闭，避免无凭据空转打点）。 */
export const ZCODE_FORK_REMOTE_BRIDGE_ENABLED: boolean =
  ZCODE_FORK_REMOTE_SERVER_URL !== "" && ZCODE_FORK_REMOTE_ENROLL_TOKEN !== "";

export const ZCODE_APP_VERSION_ENV = "ZCODE_APP_VERSION" as const;
export const ZCODE_BUILD_COMMIT_ID_ENV = "ZCODE_BUILD_COMMIT_ID" as const;

// ── 运行时环境变量（不经过编译打包，启动时从 process.env 读取） ──
// 启用调试模式，值为 inspect-brk 的端口号，如 ZCODE_DEBUG=9230
export const RUNTIME_ZCODE_DEBUG =
  typeof process !== "undefined" ? process.env.ZCODE_DEBUG : undefined;

// 恢复原因：写死 false 会让运行时已配置的数仓/ARMS 永远空转。
// 功能保持可用；实际出网由各出口的运行时端点检查决定，未配置不上报。
export const ZCODE_TELEMETRY_ENABLED: boolean = true;

/** 数仓事件上报端点：由运行时环境变量提供，未配置即停用，构建产物不内嵌。 */
export const ZCODE_TELEMETRY_REPORT_ENDPOINT =
  typeof process !== "undefined" ? (process.env.ZCODE_TELEMETRY_REPORT_ENDPOINT ?? "") : "";

/** ARMS RUM 接入端点：由运行时环境变量提供，未配置即停用，构建产物不内嵌。 */
export const ZCODE_ARMS_RUM_ENDPOINT =
  typeof process !== "undefined" ? (process.env.ZCODE_ARMS_RUM_ENDPOINT ?? "") : "";

/** 将本地运行态与编译期 ZCODE_ENV 映射为 ARMS 控制台识别的上报环境标签 */
export function mapZCodeEnvToArmsRumEnv(runtimeEnv: ZCodeRuntimeEnv): ArmsRumEnv {
  return runtimeEnv !== "development" && ZCODE_ENV === "production" ? "prod" : "local";
}
