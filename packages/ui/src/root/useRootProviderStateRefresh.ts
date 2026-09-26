import { useCallback } from "react";
import type { IServiceAccessor } from "@zcode/services";
import { logger } from "@/logger.js";

type RootProviderStateServices = Pick<IServiceAccessor, "providerSettingsService">;

async function refreshRootProviderState(services: RootProviderStateServices): Promise<void> {
  try {
    // Provider Runtime 统一刷新 Config、Account Source 与 Registry；Root 不再维护旧快照。
    await services.providerSettingsService.refresh("root-provider-state-refresh");
  } catch (error) {
    logger.error("[Root] 刷新 Provider Runtime 失败:", error);
  }
}

export function useRootProviderStateRefresh(
  services: IServiceAccessor,
  { enabled = true }: { enabled?: boolean } = {},
) {
  return useCallback(async () => {
    // 远控挂载形态（enabled=false）：providerSettingsService.refresh 只会在桥上
    // 1000ms 超时，这里直接吞掉调用，避免把 "Unknown channel: provider-settings"
    // 打进中继日志。返回已完成的 Promise 保持调用方 await 语义不变。
    if (!enabled) {
      return;
    }
    await refreshRootProviderState(services);
  }, [enabled, services.providerSettingsService]);
}
