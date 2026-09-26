/**
 * 远控桥专用 host 进程管理器（main 侧）—— DESIGN v3.1 附录 A「K0 拓扑定案」。
 *
 * 职责：app 启动（本地库就绪）后 fork 一个【无窗口】专用 host（复用 host/index.ts 入口
 * 与 InitLocal/AttachServicePort 协议），host 内经 remoteBridge.ts 常驻连接中继。
 *
 * 与 spawnHostProcess 的刻意差异（附录 A.2 落地约束）：
 * - 独立小 spawn 函数，禁止借窗复用：bindDatabaseStartupRelay 按 win WeakMap 单绑定，
 *   借窗会顶掉该窗口 host 的 DB 启动态转发。
 * - 不入 windowHostProcessMap（键=webContents id）：避免被 cuaPipFocus 路由 / cron 派发
 *   误选中。
 * - InitLocal 必须携带 MessageChannelMain 端口（host/index.ts 对无 port 消息先 return，
 *   静默丢弃）；main 持留 port1，不转发给任何 renderer。
 * - 退出屏障：dispose 并入 prepareAppQuit（照 desktopCronScheduler 先例，复用
 *   disposeHostProcessAndWait 的优雅 Dispose 时序）。
 * - 进程意外退出：抖动退避 respawn（设备在线=app 进程生命周期，DESIGN §附录 A.6 叙事）。
 */
import { MessageChannelMain, utilityProcess as electronUtilityProcess } from "electron";
import type { MessagePortMain, UtilityProcess as ElectronUtilityProcess } from "electron";
import {
  ZCODE_FORK_REMOTE_BRIDGE_ENABLED,
  HostResponseTypes,
  hostResponseMessageSchema,
} from "@zcode/shared";
import { buildHostProcessEnv, hostModulePath } from "./desktopRuntimeEnv.js";
import { createHostLogRelay } from "./hostLogRelay.js";
import { disposeHostProcessAndWait } from "./desktopHostProcess.js";

/** 桥 host 进程身份标记；host/index.ts 据此（+构建期常量）启动 remoteBridge。 */
export const REMOTE_BRIDGE_HOST_ENV = "ZCODE_REMOTE_BRIDGE_HOST";
export const REMOTE_BRIDGE_PROCESS_LABEL = "remote-bridge-host";

const RESPAWN_BASE_DELAY_MS = 2_000;
const RESPAWN_MAX_DELAY_MS = 60_000;

interface RemoteBridgeHostDeps {
  hostProcessLocalEnv: Record<string, string>;
  logger: {
    info: (...args: unknown[]) => void;
    warn: (...args: unknown[]) => void;
    error: (...args: unknown[]) => void;
  };
  /** InitLocal 必填：Built-in Provider Config 路径（main 解析）。 */
  zcodeBuiltinProviderConfigFilePath: string;
  deviceMid?: string;
  /** Agent spawn 的 cwd 兜底（conversation workspace 目录）。 */
  agentSpawnFallbackCwd?: string;
  runtimeProcessEnvPatch?: Record<string, string>;
}

export interface RemoteBridgeHostHandle {
  /** 优雅收尾：发 Dispose、等待 host 清理（agent 树收口），超时强杀。 */
  dispose: () => Promise<void>;
}

function computeRespawnDelayMs(exitCount: number): number {
  const exponential = Math.min(
    RESPAWN_BASE_DELAY_MS * 2 ** Math.max(exitCount - 1, 0),
    RESPAWN_MAX_DELAY_MS,
  );
  return Math.floor(Math.random() * exponential) + 1;
}

export function spawnRemoteBridgeHostProcess(
  deps: RemoteBridgeHostDeps,
): RemoteBridgeHostHandle | null {
  if (!ZCODE_FORK_REMOTE_BRIDGE_ENABLED) {
    // 构建期未烧入 URL/token：整模块静默关闭（不出网、不 spawn），同无 feed 时更新链全关。
    deps.logger.info("[remote-bridge] disabled: ZCODE_FORK_REMOTE_SERVER_URL/token not baked in");
    return null;
  }

  let disposed = false;
  let disposePromise: Promise<void> | null = null;
  let respawnTimer: ReturnType<typeof setTimeout> | null = null;
  let unexpectedExitCount = 0;
  let child: ElectronUtilityProcess | null = null;
  const disposingHostProcessTimers = new WeakMap<
    ElectronUtilityProcess,
    ReturnType<typeof setTimeout>
  >();

  const retainedPorts: MessagePortMain[] = [];

  const spawnOnce = (): void => {
    child = electronUtilityProcess.fork(hostModulePath, [], {
      serviceName: "zcode-remote-bridge-host",
      execArgv: ["--no-warnings"],
      env: {
        ...buildHostProcessEnv(deps.hostProcessLocalEnv),
        [REMOTE_BRIDGE_HOST_ENV]: "1",
        ZCODE_PROCESS_LABEL: REMOTE_BRIDGE_PROCESS_LABEL,
      },
    });
    deps.logger.info(`[remote-bridge] forked bridge host process pid=${child.pid}`);

    const hostLogRelay = createHostLogRelay(
      REMOTE_BRIDGE_PROCESS_LABEL,
      deps.logger as Parameters<typeof createHostLogRelay>[1],
    );
    child.stderr?.on("data", (data: Buffer) => {
      hostLogRelay.onStderr(data.toString());
    });
    child.stdout?.on("data", (data: Buffer) => {
      hostLogRelay.onStdout(data.toString());
    });

    child.on("message", (message: unknown) => {
      const result = hostResponseMessageSchema.safeParse(message);
      if (!result.success) {
        return;
      }
      // 无窗口 host 没有转发目标；DB 启动态/遥测只落 main 日志，桥在线态由
      // remote-bridge 自身日志呈现（host 侧 DatabaseStartupState phase=ready 是服务就绪前提）。
      if (result.data.type === HostResponseTypes.DatabaseStartupState) {
        deps.logger.info(`[remote-bridge] host database startup phase=${result.data.state.phase}`);
        return;
      }
      // 结构化日志与窗口 host 同接线（desktopHostProcess.ts Log 分支）：host 的
      // 双通道（stdout/stderr + postMessage Log）由 hostLogRelay 去重，这里不接
      // 就等于把结构化通道静默丢弃。
      if (result.data.type === HostResponseTypes.Log) {
        hostLogRelay.onStructuredLog(result.data);
        return;
      }
    });

    let retainedPort: MessagePortMain | null = null;
    child.on("exit", (code) => {
      hostLogRelay.flushRawLogs();
      // 退出即关闭该 child 的持留端口并出列：否则每次意外退出→respawn 都会滞留一个
      // MessagePortMain，崩溃循环下无限累积（此前只有 dispose() 统一清扫）。
      if (retainedPort) {
        const retainedPortRef = retainedPort;
        retainedPort = null;
        const index = retainedPorts.indexOf(retainedPortRef);
        if (index >= 0) {
          retainedPorts.splice(index, 1);
        }
        try {
          retainedPortRef.close();
        } catch {
          // 已关闭。
        }
      }
      if (child) {
        deps.logger.info(
          `[remote-bridge] bridge host process exited code=${code} pid=${child.pid ?? "unknown"}`,
        );
      }
      child = null;
      if (disposed || respawnTimer) {
        return;
      }
      unexpectedExitCount += 1;
      const delayMs = computeRespawnDelayMs(unexpectedExitCount);
      deps.logger.warn(
        `[remote-bridge] bridge host exited unexpectedly (count=${unexpectedExitCount}); respawn in ${delayMs}ms`,
      );
      respawnTimer = setTimeout(() => {
        respawnTimer = null;
        if (!disposed) {
          spawnOnce();
        }
      }, delayMs);
      respawnTimer.unref?.();
    });

    // InitLocal 协议要求：必须带 MessageChannelMain 端口（无 port 会被 host 静默丢弃）。
    // port1 由 main 持留（不挂任何 renderer/consumer），仅保持 host 基础 attachment 存活；
    // child 退出时在 exit handler 里关闭出列（见上），dispose() 只兜底收尾。
    const { port1, port2 } = new MessageChannelMain();
    child.postMessage(
      {
        type: "init-local",
        deviceMid: deps.deviceMid,
        agentSpawnFallbackCwd: deps.agentSpawnFallbackCwd,
        runtimeProcessEnvPatch: deps.runtimeProcessEnvPatch,
        zcodeBuiltinProviderConfigFilePath: deps.zcodeBuiltinProviderConfigFilePath,
      },
      [port2],
    );
    retainedPort = port1;
    retainedPorts.push(port1);
  };

  spawnOnce();

  return {
    dispose() {
      if (disposePromise) {
        return disposePromise;
      }
      disposed = true;
      if (respawnTimer) {
        clearTimeout(respawnTimer);
        respawnTimer = null;
      }
      disposePromise = (async () => {
        // 持留端口关闭，避免退出窗口期残留 attachment。
        for (const port of retainedPorts.splice(0)) {
          try {
            port.close();
          } catch {
            // 已关闭。
          }
        }
        const exitingChild = child;
        child = null;
        if (!exitingChild) {
          return;
        }
        await disposeHostProcessAndWait(
          exitingChild,
          REMOTE_BRIDGE_PROCESS_LABEL,
          disposingHostProcessTimers,
          deps.logger,
          // 与窗口 host 同级的优雅预算：≥3.5s 等 agent 树收口（disposeHostProcess 内有下限）。
          { forceKillDelayMs: 3_500, waitTimeoutMs: 8_000 },
        );
      })();
      return disposePromise;
    },
  };
}
