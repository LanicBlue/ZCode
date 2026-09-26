import { create } from "zustand";
import type { ServerRemoteWorkspaceInfo } from "@zcode/shared";

/**
 * 远控 Web 会话（/?remote=<deviceId> 经中继挂载桌面）的 renderer 级会话事实。
 *
 * 为什么走模块 store 而不是 props 逐层下传：消费方（WorkspaceSidebarFooter 的账号区、
 * WorkspaceSidebar 的设备工作区切换区）位于 App→WorkspaceShellLayout 深处，逐层补 props
 * 需要改动 5+ 个纯透传层；这里沿用 mcpStore 平台标记（Root effect 写入、深层组件订阅）
 * 的既有模式，写入点唯一（Root 挂载时一次）。
 */
interface RemoteWebSessionState {
  /** 当前 renderer 是否为 ?remote= 远控挂载形态。 */
  enabled: boolean;
  /** 中继 server-info 合成的设备工作区列表（路径来自设备侧 settingService 投影）。 */
  deviceWorkspaces: readonly ServerRemoteWorkspaceInfo[];
  setRemoteWebSession: (options: {
    enabled: boolean;
    deviceWorkspaces?: readonly ServerRemoteWorkspaceInfo[];
  }) => void;
}

const EMPTY_WORKSPACES: readonly ServerRemoteWorkspaceInfo[] = [];

export const useRemoteWebSessionStore = create<RemoteWebSessionState>((set) => ({
  enabled: false,
  deviceWorkspaces: EMPTY_WORKSPACES,
  setRemoteWebSession: ({ enabled, deviceWorkspaces }) =>
    set({ enabled, deviceWorkspaces: deviceWorkspaces ?? EMPTY_WORKSPACES }),
}));

/** 远控挂载形态标记：账号区隐藏等 UI 降级判定用。 */
export function useIsRemoteWebSession(): boolean {
  return useRemoteWebSessionStore((state) => state.enabled);
}

/** 设备工作区列表（非远控形态恒为空）。 */
export function useRemoteDeviceWorkspaces(): readonly ServerRemoteWorkspaceInfo[] {
  return useRemoteWebSessionStore((state) => state.deviceWorkspaces);
}
