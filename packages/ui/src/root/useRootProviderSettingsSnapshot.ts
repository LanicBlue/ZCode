import { useEffect } from "react";
import type { IServiceAccessor } from "@zcode/services";
import { connectProviderSettingsSnapshot } from "@/lib/providerSettingsSnapshot.js";
import { logger } from "@/logger.js";

export function useRootProviderSettingsSnapshot(
  services: IServiceAccessor,
  { enabled = true }: { enabled?: boolean } = {},
): void {
  useEffect(() => {
    const service = services.providerSettingsService;
    if (!service || !enabled) return;

    const connection = connectProviderSettingsSnapshot(service);
    void connection.ready.catch((error) => {
      logger.warn("[Root] 加载 Provider Settings View 失败", {
        error,
      });
    });
    return () => connection.dispose();
  }, [enabled, services.providerSettingsService]);
}
