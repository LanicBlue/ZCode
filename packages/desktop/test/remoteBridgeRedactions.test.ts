import assert from "node:assert/strict";
import test from "node:test";
import {
  REMOTE_BRIDGE_CREDENTIAL_PRESENT_PLACEHOLDER,
  REMOTE_BRIDGE_SERVICE_WHITELIST,
  createReadOnlyCredentialService,
  createReadOnlyCodingPlanSubscriptionService,
  createReadOnlyOAuthService,
  createReadOnlyUsageStatsService,
  createRedactedProviderSettingsService,
  createRemoteBridgeConnectionResources,
  createWindowControllerRpcSurface,
  isRemoteBridgeRedactedService,
  redactOffPeakClientConfig,
  redactProviderSettingsView,
  registerRedactedChannel,
  resolveRemoteBridgeChannelRuling,
  resolveRemoteBridgeCredentialKeyRuling,
} from "../src/host/remoteBridge.js";
import {
  ICodingPlanSubscriptionService,
  ICredentialService,
  IOAuthService,
  IProviderSettingsService,
  IUsageStatsService,
  IWindowControllerService,
  type OffPeakClientConfig,
  type ProviderSettingsView,
} from "@zcode/services";
import type { ChannelServer } from "@zcode/rpc";
import {
  DEFAULT_RELAY_DEVICE_SERVICE_WHITELIST,
  RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS,
  RELAY_FORBIDDEN_DEVICE_SERVICES,
} from "@zcode/server";

// ── fakes ───────────────────────────────────────────────────────────────────

/**
 * 模拟真实 OAuthService 的写副作用面：restoreCachedSessionState/restoreSession/
 * logout 在设备端会 clearActiveSession + 删派生 key（security review Major 2）。
 * dry 包装必须只触碰 getProviders/getActiveProvider/peekCachedSessionState。
 */
function createFakeOAuthService(): IOAuthService & {
  calls: string[];
  destructiveCalls: number[];
} {
  const calls: string[] = [];
  const destructiveCalls: number[] = [];
  const record = <T>(name: string, value: T): T => {
    calls.push(name);
    return value;
  };
  const destructive = async (name: string): Promise<never> => {
    calls.push(name);
    destructiveCalls.push(Date.now());
    throw new Error(`destructive ${name} leaked to the device service`);
  };
  return {
    calls,
    destructiveCalls,
    getProviders: async () =>
      record("getProviders", [{ id: "zai", displayName: "Z.AI", enabled: true, order: 1 }]),
    getActiveProvider: async () => record("getActiveProvider", "zai"),
    peekCachedSessionState: async () =>
      record("peekCachedSessionState", {
        status: "authenticated",
        userInfo: { id: "u1", username: "alice", displayName: "Alice" },
      }),
    restoreCachedSession: () => destructive("restoreCachedSession"),
    restoreCachedSessionState: () => destructive("restoreCachedSessionState"),
    restoreSession: () => destructive("restoreSession"),
    startOAuth: () => destructive("startOAuth"),
    startOAuthWithPolling: () => destructive("startOAuthWithPolling"),
    pollPendingOAuth: () => destructive("pollPendingOAuth"),
    handleCallback: () => destructive("handleCallback"),
    refreshToken: () => destructive("refreshToken"),
    logout: () => destructive("logout"),
    logoutAll: () => destructive("logoutAll"),
    cancelPending: () => destructive("cancelPending"),
  };
}

function buildProviderSettingsView(): ProviderSettingsView {
  return {
    revision: 7,
    providerOrder: ["personal-openai"],
    providerTemplates: [
      {
        templateId: "openai",
        templateNameMap: {},
        config: {
          access: { type: "api-key", apiKey: "tpl-key", apiKeyManagementUrl: "https://tpl.manage" },
          api: {
            type: "openai",
            baseUrl: "https://tpl.example",
            headers: { Authorization: "Bearer tpl-secret" },
          },
        },
      },
    ],
    providers: [
      {
        enabled: true,
        providerId: "personal-openai",
        executable: true,
        effectiveConfig: {
          access: { type: "api-key", apiKey: "eff-key", apiKeyManagementUrl: "https://eff.manage" },
          api: {
            type: "openai",
            baseUrl: "https://eff.example",
            headers: { Authorization: "Bearer eff-secret" },
          },
        },
        personalConfig: {
          access: { type: "api-key", apiKey: "personal-key" },
          api: { headers: { "x-api-key": "personal-secret" } },
        },
        effectiveBuiltinConfig: {
          api: { headers: { Authorization: "builtin-secret" } },
        },
        accountState: { availability: "available", entitled: true, connectionKey: "conn-1" },
        issues: [],
        models: [],
      },
    ],
  } as unknown as ProviderSettingsView;
}

function createFakeProviderSettingsService(view: ProviderSettingsView): IProviderSettingsService & {
  changeListeners: Array<(view: ProviderSettingsView) => void>;
  refreshCalls: () => number;
} {
  const changeListeners: Array<(view: ProviderSettingsView) => void> = [];
  let refreshCallCount = 0;
  const refuse = (name: string) => async () => {
    throw new Error(`underlying ${name} must not be called on the remote bridge`);
  };
  return {
    changeListeners,
    refreshCalls: () => refreshCallCount,
    getView: async () => view,
    refresh: async () => {
      refreshCallCount += 1;
      return view;
    },
    onDidChange: (listener) => {
      changeListeners.push(listener);
      return { dispose() {} };
    },
    createPersonalProvider: refuse("createPersonalProvider"),
    resolveModelConfig: refuse("resolveModelConfig"),
    savePersonalProviderOverlay: refuse("savePersonalProviderOverlay"),
    deletePersonalProvider: refuse("deletePersonalProvider"),
    reorderPersonalProviders: refuse("reorderPersonalProviders"),
    reorderPersonalModels: refuse("reorderPersonalModels"),
    addPersonalModel: refuse("addPersonalModel"),
    renamePersonalModel: refuse("renamePersonalModel"),
    deletePersonalModel: refuse("deletePersonalModel"),
    savePersonalModelDraft: refuse("savePersonalModelDraft"),
    setPersonalModelEnabled: refuse("setPersonalModelEnabled"),
    testModelConnectivity: refuse("testModelConnectivity"),
  };
}

/**
 * 模拟真实 CredentialStore 的键值面：store 里的真值（含 token 真值）绝不能
 * 原样穿过包装；deny-first 断言还要求白名单外的键根本不触底（不构成存在性预言机）。
 */
function createFakeCredentialService(
  entries: Record<string, string | null> = {},
): ICredentialService & { loadedKeys: string[]; writeCalls: string[] } {
  const loadedKeys: string[] = [];
  const writeCalls: string[] = [];
  return {
    loadedKeys,
    writeCalls,
    load: async (key) => {
      loadedKeys.push(key);
      return key in entries ? ((entries[key] ?? null) as string | null) : null;
    },
    save: async (key) => {
      writeCalls.push(`save:${key}`);
    },
    delete: async (key) => {
      writeCalls.push(`delete:${key}`);
    },
  };
}

// ── oauth：dry 观察、写侧全拒、错误消毒 ──────────────────────────────────────

test("read-only oauth service synthesizes dry session state without touching device writes", async () => {
  const fake = createFakeOAuthService();
  const wrapped = createReadOnlyOAuthService(fake);

  assert.equal(await wrapped.getActiveProvider(), "zai");
  const state = await wrapped.restoreCachedSessionState();
  assert.equal(state.status, "authenticated");
  assert.equal(state.userInfo?.username, "alice");
  const user = await wrapped.restoreCachedSession();
  assert.equal(user?.username, "alice");
  // dry 读只允许触碰纯读方法；任何带写副作用的底层方法被调用都会让 fake 抛错，
  // destructiveCalls 同时兜底断言（logout/clearActiveSession 类清理计数必须为 0）。
  assert.deepEqual(fake.calls, [
    "getActiveProvider",
    "peekCachedSessionState",
    "peekCachedSessionState",
  ]);
  assert.deepEqual(fake.destructiveCalls, []);
});

test("read-only oauth service maps dry state to signed-out without device cleanup", async () => {
  const fake = createFakeOAuthService();
  fake.peekCachedSessionState = async () => ({ status: "signed-out" });
  const wrapped = createReadOnlyOAuthService(fake);

  assert.deepEqual(await wrapped.restoreCachedSessionState(), { status: "signed-out" });
  assert.equal(await wrapped.restoreCachedSession(), null);
  assert.deepEqual(fake.destructiveCalls, []);
});

test("read-only oauth service rejects every write/flow method without touching the device service", () => {
  const fake = createFakeOAuthService();
  const wrapped = createReadOnlyOAuthService(fake);
  const rejections: Array<() => unknown> = [
    () => wrapped.restoreSession(),
    () => wrapped.peekCachedSessionState(),
    () => wrapped.startOAuth("zai"),
    () => wrapped.startOAuthWithPolling("zai"),
    () => wrapped.pollPendingOAuth(),
    () => wrapped.handleCallback("https://callback.example"),
    () => wrapped.refreshToken(),
    () => wrapped.logout(),
    () => wrapped.logoutAll(),
    () => wrapped.cancelPending(),
  ];
  for (const attempt of rejections) {
    assert.throws(
      attempt,
      /oauth\.\w+ is not available on the remote bridge \(read-only channel\)/,
    );
  }
  assert.deepEqual(fake.calls, [], "write-side rejection must not reach the underlying service");
  assert.deepEqual(fake.destructiveCalls, []);
});

test("oauth read errors are sanitized (message kept, stack and passthrough fields dropped)", async () => {
  const fake = createFakeOAuthService();
  const leaky = new Error("device oauth store failed");
  leaky.stack = "Error: device oauth store failed\n    at /Users/device/zcode/packages/...";
  (leaky as Error & { code?: unknown }).code = "DEVICE_INTERNAL_CODE";
  fake.getProviders = async () => {
    throw leaky;
  };
  const wrapped = createReadOnlyOAuthService(fake);

  const caught = await wrapped.getProviders().then(
    () => null,
    (error: unknown) => error,
  );
  assert.ok(caught instanceof Error);
  assert.equal(caught.message, "device oauth store failed");
  assert.equal(caught.stack, undefined);
  assert.equal((caught as Error & { code?: unknown }).code, undefined);
});

// ── provider-settings：读侧脱敏、写侧全拒、消毒、限频 ───────────────────────

test("redacted provider-settings view strips apiKey/apiKeyManagementUrl/headers from all config faces", async () => {
  const view = buildProviderSettingsView();
  const wrapped = createRedactedProviderSettingsService(createFakeProviderSettingsService(view));

  const redacted = await wrapped.getView();
  const provider = redacted.providers[0]!;
  for (const config of [
    provider.effectiveConfig,
    provider.personalConfig,
    provider.effectiveBuiltinConfig,
  ]) {
    assert.equal(config?.access?.apiKey, undefined);
    assert.equal(config?.access?.apiKeyManagementUrl, undefined);
    assert.equal(config?.api?.headers, undefined);
  }
  // 非凭据字段保留：api.type/baseUrl、access.type、accountState、模板元数据。
  assert.equal(provider.effectiveConfig.api?.type, "openai");
  assert.equal(provider.effectiveConfig.api?.baseUrl, "https://eff.example");
  assert.equal(provider.effectiveConfig.access?.type, "api-key");
  assert.equal(provider.accountState?.availability, "available");
  assert.equal(provider.accountState?.entitled, true);
  const templateConfig = redacted.providerTemplates[0]!.config;
  assert.equal(templateConfig.access?.apiKey, undefined);
  assert.equal(templateConfig.access?.apiKeyManagementUrl, undefined);
  assert.equal(templateConfig.api?.headers, undefined);
  assert.equal(templateConfig.api?.baseUrl, "https://tpl.example");
  // 原对象不被就地改写（脱敏只做浅拷贝，宿主侧事实保持完整）。
  assert.equal(view.providers[0]!.effectiveConfig.access?.apiKey, "eff-key");
});

test("redacted provider-settings view keeps credential-free views untouched (same reference)", async () => {
  const cleanView = {
    revision: 3,
    providerOrder: ["builtin"],
    providerTemplates: [
      { templateId: "t", templateNameMap: {}, config: { api: { type: "openai" } } },
    ],
    providers: [
      {
        enabled: true,
        providerId: "builtin",
        executable: true,
        effectiveConfig: { access: { type: "zhipu-account", entitled: true } },
        issues: [],
        models: [],
      },
    ],
  } as unknown as ProviderSettingsView;
  const wrapped = createRedactedProviderSettingsService(
    createFakeProviderSettingsService(cleanView),
  );
  assert.strictEqual(await wrapped.getView(), cleanView);
});

test("redactProviderSettingsView passes unknown shapes through unchanged", () => {
  const providers = [null, 42, {}, { personalConfig: "not-an-object" }];
  const providerTemplates = [{ config: null }, "junk"];
  const view = { revision: 1, providers, providerTemplates } as ProviderSettingsView;
  const result = redactProviderSettingsView(view);
  assert.strictEqual(result, view);
  assert.strictEqual(result.providers, providers);
  assert.strictEqual(result.providerTemplates, providerTemplates);
});

test("redacted provider-settings service filters onDidChange events too", async () => {
  const fake = createFakeProviderSettingsService(buildProviderSettingsView());
  const wrapped = createRedactedProviderSettingsService(fake);
  const received: ProviderSettingsView[] = [];
  wrapped.onDidChange((view) => received.push(view));

  assert.equal(fake.changeListeners.length, 1);
  fake.changeListeners[0]!(buildProviderSettingsView());
  assert.equal(received.length, 1);
  const event = received[0]!;
  assert.equal(event.providers[0]!.effectiveConfig.access?.apiKey, undefined);
  assert.equal(event.providers[0]!.personalConfig?.api?.headers, undefined);
  assert.equal(event.providerTemplates[0]!.config.access?.apiKey, undefined);
});

test("redacted provider-settings service rejects every mutation", () => {
  const fake = createFakeProviderSettingsService(buildProviderSettingsView());
  const wrapped = createRedactedProviderSettingsService(fake);
  const rejections: Array<() => unknown> = [
    () => wrapped.createPersonalProvider(),
    () => wrapped.resolveModelConfig({ providerId: "p", modelId: "m" }),
    () => wrapped.savePersonalProviderOverlay("p", {}),
    () => wrapped.deletePersonalProvider("p"),
    () => wrapped.reorderPersonalProviders(["p"]),
    () => wrapped.reorderPersonalModels("p", ["m"]),
    () => wrapped.addPersonalModel("p", "m", {} as never),
    () => wrapped.renamePersonalModel("p", "m", "m2"),
    () => wrapped.deletePersonalModel("p", "m"),
    () => wrapped.savePersonalModelDraft({} as never),
    () => wrapped.setPersonalModelEnabled("p", "m", false),
    () => wrapped.testModelConnectivity({ workspacePath: "/w", providerId: "p", modelId: "m" }),
  ];
  for (const attempt of rejections) {
    assert.throws(
      attempt,
      /provider-settings\.\w+ is not available on the remote bridge \(read-only channel\)/,
    );
  }
  assert.equal(fake.refreshCalls(), 0, "mutations must not reach the underlying service");
});

test("provider-settings read errors are sanitized (no device stack)", async () => {
  const fake = createFakeProviderSettingsService(buildProviderSettingsView());
  const leaky = new Error("registry read failed");
  leaky.stack = "Error: registry read failed\n    at /Users/device/zcode/out/host/...";
  fake.getView = async () => {
    throw leaky;
  };
  const wrapped = createRedactedProviderSettingsService(fake);

  const caught = await wrapped.getView().then(
    () => null,
    (error: unknown) => error,
  );
  assert.ok(caught instanceof Error);
  assert.equal(caught.message, "registry read failed");
  assert.equal(caught.stack, undefined);
});

test("provider-settings refresh is rate limited per wrapper instance and replays the last view", async () => {
  const fake = createFakeProviderSettingsService(buildProviderSettingsView());
  const wrapped = createRedactedProviderSettingsService(fake);

  const results: ProviderSettingsView[] = [];
  for (let index = 0; index < 9; index += 1) {
    results.push(await wrapped.refresh(`burst-${index}`));
  }
  // 60s 窗口内最多 6 次真实 refresh；第 7 次起回放最近一次成功 view（引用相同）。
  assert.equal(fake.refreshCalls(), 6);
  assert.strictEqual(results[6], results[5]);
  assert.strictEqual(results[8], results[5]);
  for (const view of results) {
    assert.equal(
      view.providers[0]!.effectiveConfig.access?.apiKey,
      undefined,
      "replayed view stays redacted",
    );
  }
});

// ── credential：键策略只读、真值绝不出设备、写侧全拒 ─────────────────────────

test("credential key policy table: passthrough for selector/user_info, presence for token keys, deny for everything else", () => {
  // passthrough：provider id 选择器 + 展示载荷（packages/ui 无 user_info 直读调用点，
  // 键位与 services oauthCredentialRepo userInfoKey 对齐留口）。
  assert.equal(resolveRemoteBridgeCredentialKeyRuling("oauth:active_provider"), "passthrough");
  assert.equal(resolveRemoteBridgeCredentialKeyRuling("oauth:zai:user_info"), "passthrough");
  assert.equal(resolveRemoteBridgeCredentialKeyRuling("oauth:bigmodel:user_info"), "passthrough");
  // presence：token 类键（真值即机密）。
  for (const key of [
    "oauth:zai:access_token",
    "oauth:bigmodel:access_token",
    "oauth:zai:refresh_token",
    "oauth:bigmodel:id_token",
    "oauth:zai:purchase_token",
    "zcodejwttoken",
  ]) {
    assert.equal(resolveRemoteBridgeCredentialKeyRuling(key), "presence", key);
  }
  // deny：其余一切键（bot/web-remote-control/account-provider/SSH workspace 凭据/
  // legacy auth_token/形状不符的 oauth 变体）。
  for (const key of [
    "bot:telegram:token",
    "web-remote-control:secret",
    "account-provider:zai:credential",
    "remote-workspace:ws-1:password",
    "remote-workspace:ws-1:private-key-passphrase",
    "auth_token",
    "oauth:zai:access_token_extra",
    "oauth:zai:devicetoken",
    "oauth:zai:user_info_extra",
    "oauth:active_provider:extra",
    "",
  ]) {
    assert.equal(resolveRemoteBridgeCredentialKeyRuling(key), null, key);
  }
});

test("read-only credential service returns original value for active_provider and user_info", async () => {
  const fake = createFakeCredentialService({
    "oauth:active_provider": "zai",
    "oauth:bigmodel:user_info": '{"id":"u1","username":"alice"}',
  });
  const wrapped = createReadOnlyCredentialService(fake);

  // 原版设置页的实际消费：activeProvider 与 provider id 等值比较（选择器，非机密）。
  assert.equal(await wrapped.load("oauth:active_provider"), "zai");
  assert.equal(await wrapped.load("oauth:bigmodel:user_info"), '{"id":"u1","username":"alice"}');
  assert.deepEqual(fake.loadedKeys, ["oauth:active_provider", "oauth:bigmodel:user_info"]);
});

test("read-only credential service maps token keys to a presence placeholder and never leaks real values", async () => {
  const realAccessToken = "sk-real-zai-access-token";
  const realJwt = "eyJhbGciOi.real.jwt";
  const fake = createFakeCredentialService({
    "oauth:zai:access_token": realAccessToken,
    "oauth:bigmodel:refresh_token": "  ",
    zcodejwttoken: realJwt,
  });
  const wrapped = createReadOnlyCredentialService(fake);

  const returned: Array<string | null> = [
    await wrapped.load("oauth:zai:access_token"),
    await wrapped.load("oauth:bigmodel:refresh_token"),
    await wrapped.load("zcodejwttoken"),
    await wrapped.load("oauth:bigmodel:access_token"),
  ];
  // 真值非空 → 固定占位；空串/null/纯空白 → null（消费方 .trim().length > 0 存在性语义）。
  assert.deepEqual(returned, [
    REMOTE_BRIDGE_CREDENTIAL_PRESENT_PLACEHOLDER,
    null,
    REMOTE_BRIDGE_CREDENTIAL_PRESENT_PLACEHOLDER,
    null,
  ]);
  for (const value of returned) {
    assert.equal(
      typeof value === "string" && (value.includes("sk-real") || value.includes("eyJhbGciOi")),
      false,
      "real token value must never leave the device",
    );
  }
});

test("read-only credential service rejects unknown keys deny-first without touching the device store", async () => {
  const fake = createFakeCredentialService({ "bot:telegram:token": "bot-secret" });
  const wrapped = createReadOnlyCredentialService(fake);

  for (const key of [
    "bot:telegram:token",
    "web-remote-control:secret",
    "account-provider:zai:credential",
    "remote-workspace:ws-1:password",
    "auth_token",
  ]) {
    await assert.rejects(
      wrapped.load(key),
      /credential\.load key '.*' is not available on the remote bridge \(read-only key policy\)/,
      key,
    );
  }
  // deny-first：白名单外的键根本不触底——桥不构成任意键的存在性预言机。
  assert.deepEqual(fake.loadedKeys, []);
  assert.deepEqual(fake.writeCalls, []);
});

test("read-only credential service rejects save/delete without touching the device store", () => {
  const fake = createFakeCredentialService();
  const wrapped = createReadOnlyCredentialService(fake);

  assert.throws(
    () => wrapped.save("oauth:zai:access_token", "captured-value"),
    /credential\.save is not available on the remote bridge \(read-only channel\)/,
  );
  assert.throws(
    () => wrapped.delete("oauth:zai:access_token"),
    /credential\.delete is not available on the remote bridge \(read-only channel\)/,
  );
  assert.deepEqual(fake.loadedKeys, []);
  assert.deepEqual(fake.writeCalls, []);
});

test("credential read errors are sanitized (no device stack)", async () => {
  const fake = createFakeCredentialService();
  const leaky = new Error("credential store decrypt failed");
  leaky.stack = "Error: credential store decrypt failed\n    at /Users/device/.zcode/...";
  (leaky as Error & { code?: unknown }).code = "KEYCHAIN_STATUS";
  fake.load = async () => {
    throw leaky;
  };
  const wrapped = createReadOnlyCredentialService(fake);

  const caught = await wrapped.load("oauth:active_provider").then(
    () => null,
    (error: unknown) => error,
  );
  assert.ok(caught instanceof Error);
  assert.equal(caught.message, "credential store decrypt failed");
  assert.equal(caught.stack, undefined);
  assert.equal((caught as Error & { code?: unknown }).code, undefined);
});

// ── usage-stats：读面放行、供应商侧重置动作全拒、消毒 ────────────────────────

/**
 * 模拟真实 UsageStatsService：读方法可触底（设备侧代取——真凭据只在此侧用于调
 * 供应商统计接口）；useCodingPlanReset/requestCodingPlanResetOpportunity/
 * markCodingPlanResetHistoryRead 是供应商侧动作，包装外绝不允许触底。
 */
function createFakeUsageStatsService(): IUsageStatsService & { calls: string[] } {
  const calls: string[] = [];
  const read = (name: string, value: unknown): unknown => {
    calls.push(name);
    return value;
  };
  const vendorMutation = (name: string): Promise<never> => {
    calls.push(name);
    return Promise.reject(new Error(`vendor mutation ${name} leaked to the device service`));
  };
  return {
    calls,
    getAppUsageSnapshot: async () =>
      read("getAppUsageSnapshot", { range: "7d", source: "agent-db", summary: { totalTokens: 1 } }),
    getCodingPlanUsageSnapshot: async () =>
      read("getCodingPlanUsageSnapshot", { range: "today", quota: { level: null, limits: [] } }),
    getCodingPlanResetStatus: async () =>
      read("getCodingPlanResetStatus", {
        availableFiveHourResets: [],
        availableWeekResets: [],
        hasUnreadHistory: false,
      }),
    getSnapshot: async () => read("getSnapshot", { range: "7d", summary: { totalSessions: 2 } }),
    getEntitlementSnapshot: async () =>
      read("getEntitlementSnapshot", { authenticated: true, remaining: { count: 5, isShow: true } }),
    requestCodingPlanResetOpportunity: () => vendorMutation("requestCodingPlanResetOpportunity"),
    useCodingPlanReset: () => vendorMutation("useCodingPlanReset"),
    markCodingPlanResetHistoryRead: () => vendorMutation("markCodingPlanResetHistoryRead"),
  } as unknown as IUsageStatsService & { calls: string[] };
}

test("read-only usage-stats service passes the five stat reads through to the device service", async () => {
  const fake = createFakeUsageStatsService();
  const wrapped = createReadOnlyUsageStatsService(fake);

  assert.equal((await wrapped.getAppUsageSnapshot({ range: "7d" })).range, "7d");
  assert.equal((await wrapped.getCodingPlanUsageSnapshot(null as never)).range, "today");
  assert.equal((await wrapped.getCodingPlanResetStatus(null as never)).hasUnreadHistory, false);
  assert.equal((await wrapped.getSnapshot({ range: "7d" })).summary.totalSessions, 2);
  assert.equal((await wrapped.getEntitlementSnapshot()).authenticated, true);
  assert.deepEqual(fake.calls, [
    "getAppUsageSnapshot",
    "getCodingPlanUsageSnapshot",
    "getCodingPlanResetStatus",
    "getSnapshot",
    "getEntitlementSnapshot",
  ]);
});

test("read-only usage-stats service rejects vendor-side reset actions without touching the device service", () => {
  const fake = createFakeUsageStatsService();
  const wrapped = createReadOnlyUsageStatsService(fake);
  const rejections: Array<() => unknown> = [
    () => wrapped.useCodingPlanReset(null as never),
    () => wrapped.requestCodingPlanResetOpportunity(null as never),
    () => wrapped.markCodingPlanResetHistoryRead(null as never),
  ];
  for (const attempt of rejections) {
    assert.throws(
      attempt,
      /usage-stats\.\w+ is not available on the remote bridge \(read-only channel\)/,
    );
  }
  assert.deepEqual(fake.calls, [], "reset actions must not reach the device service");
});

test("usage-stats read errors are sanitized (no device stack)", async () => {
  const fake = createFakeUsageStatsService();
  const leaky = new Error("monitor api request failed");
  leaky.stack = "Error: monitor api request failed\n    at /Users/device/zcode/packages/...";
  fake.getSnapshot = async () => {
    throw leaky;
  };
  const wrapped = createReadOnlyUsageStatsService(fake);

  const caught = await wrapped.getSnapshot({ range: "7d" }).then(
    () => null,
    (error: unknown) => error,
  );
  assert.ok(caught instanceof Error);
  assert.equal(caught.message, "monitor api request failed");
  assert.equal(caught.stack, undefined);
});

// ── coding-plan-subscription：订阅读面 + 支付流全拒 + offpeak 脱敏 ───────────

function createFakeCodingPlanSubscriptionService(): ICodingPlanSubscriptionService & {
  calls: string[];
} {
  const calls: string[] = [];
  const read = (name: string, value: unknown): unknown => {
    calls.push(name);
    return value;
  };
  const paymentFlow = (name: string): Promise<never> => {
    calls.push(name);
    return Promise.reject(new Error(`payment flow ${name} leaked to the device service`));
  };
  return {
    calls,
    batchPreview: async () => read("batchPreview", { productList: [], isSubscribed: false, isAuthenticated: true }),
    getStaticProducts: async () => read("getStaticProducts", {}),
    getStaticTeamProducts: async () => read("getStaticTeamProducts", {}),
    getStartPlanPreview: async () => read("getStartPlanPreview", { planId: "start", name: "Start", entitlements: [] }),
    getOffPeakClientConfig: async () =>
      read("getOffPeakClientConfig", {
        enabled: true,
        modelSelectionView: {
          revision: 1,
          providers: [
            {
              providerId: "offpeak",
              config: {
                access: { type: "api-key", apiKey: "offpeak-real-key", apiKeyManagementUrl: "https://manage" },
                api: { type: "openai", baseUrl: "https://offpeak.example", headers: { Authorization: "Bearer offpeak-secret" } },
              },
            },
          ],
        },
      }),
    getDynamicWorkflowClientConfig: async () =>
      read("getDynamicWorkflowClientConfig", { mode: "on_demand", enabled: true, source: "remote" }),
    getModelContextBudgetStrategy: async () => read("getModelContextBudgetStrategy", "preflight-v1"),
    getForceUpdateConfig: async () => read("getForceUpdateConfig", { minimalVersion: "1.0.0" }),
    productInfo: async () => read("productInfo", { productId: "p1" }),
    preview: async () => read("preview", { productId: "p1", bizId: "b1", payAmount: 1 }),
    getEnterprisePricing: async () => read("getEnterprisePricing", { productList: [] }),
    getEnterpriseBalance: async () => read("getEnterpriseBalance", { giveBalance: 0, cashBalance: 0, totalBalance: 0 }),
    calculateEnterpriseOrder: async () =>
      read("calculateEnterpriseOrder", { totalOriginalAmount: 0, totalPayAmount: 0, thirdPayAmount: 0 }),
    getEnterprisePendingOrders: async () => read("getEnterprisePendingOrders", []),
    checkEnterpriseOrderStatus: async () =>
      read("checkEnterpriseOrderStatus", { orderNo: "o1", paymentStatus: "WAIT_PAY" }),
    createSign: () => paymentFlow("createSign"),
    updateSign: () => paymentFlow("updateSign"),
    checkPayment: () => paymentFlow("checkPayment"),
    checkPendingOrders: () => paymentFlow("checkPendingOrders"),
    queryStripeCards: () => paymentFlow("queryStripeCards"),
    bindStripeCard: () => paymentFlow("bindStripeCard"),
    unbindStripeCard: () => paymentFlow("unbindStripeCard"),
    payStripe: () => paymentFlow("payStripe"),
    checkPaypalSupport: () => paymentFlow("checkPaypalSupport"),
    createPaypalSetupToken: () => paymentFlow("createPaypalSetupToken"),
    subscribePaypal: () => paymentFlow("subscribePaypal"),
    createEnterpriseOrder: () => paymentFlow("createEnterpriseOrder"),
    cancelEnterpriseOrder: () => paymentFlow("cancelEnterpriseOrder"),
    continueEnterpriseOrderPayment: () => paymentFlow("continueEnterpriseOrderPayment"),
  } as unknown as ICodingPlanSubscriptionService & { calls: string[] };
}

test("read-only coding-plan-subscription service passes catalog/pricing/order-status reads through", async () => {
  const fake = createFakeCodingPlanSubscriptionService();
  const wrapped = createReadOnlyCodingPlanSubscriptionService(fake);

  assert.equal((await wrapped.batchPreview()).isAuthenticated, true);
  assert.deepEqual(await wrapped.getStaticProducts(), {});
  assert.deepEqual(await wrapped.getStaticTeamProducts(), {});
  assert.equal((await wrapped.getStartPlanPreview()).planId, "start");
  assert.equal((await wrapped.getOffPeakClientConfig()).enabled, true);
  assert.equal((await wrapped.getDynamicWorkflowClientConfig()).enabled, true);
  assert.equal(await wrapped.getModelContextBudgetStrategy(), "preflight-v1");
  assert.equal((await wrapped.getForceUpdateConfig()).minimalVersion, "1.0.0");
  assert.equal((await wrapped.productInfo(null as never)).productId, "p1");
  assert.equal((await wrapped.preview(null as never)).bizId, "b1");
  assert.equal((await wrapped.getEnterprisePricing(null as never)).productList.length, 0);
  assert.equal((await wrapped.getEnterpriseBalance()).totalBalance, 0);
  assert.equal((await wrapped.calculateEnterpriseOrder(null as never)).thirdPayAmount, 0);
  assert.equal((await wrapped.getEnterprisePendingOrders()).length, 0);
  assert.equal((await wrapped.checkEnterpriseOrderStatus(null as never)).orderNo, "o1");
  assert.deepEqual(fake.calls, [
    "batchPreview",
    "getStaticProducts",
    "getStaticTeamProducts",
    "getStartPlanPreview",
    "getOffPeakClientConfig",
    "getDynamicWorkflowClientConfig",
    "getModelContextBudgetStrategy",
    "getForceUpdateConfig",
    "productInfo",
    "preview",
    "getEnterprisePricing",
    "getEnterpriseBalance",
    "calculateEnterpriseOrder",
    "getEnterprisePendingOrders",
    "checkEnterpriseOrderStatus",
  ]);
});

test("read-only coding-plan-subscription service strips credentials from getOffPeakClientConfig's embedded modelSelectionView", async () => {
  const fake = createFakeCodingPlanSubscriptionService();
  const wrapped = createReadOnlyCodingPlanSubscriptionService(fake);

  const config = await wrapped.getOffPeakClientConfig();
  const provider = config.modelSelectionView.providers[0] as unknown as {
    config: {
      access: Record<string, unknown> | undefined;
      api: Record<string, unknown> | undefined;
    };
  };
  assert.equal(provider.config.access?.apiKey, undefined);
  assert.equal(provider.config.access?.apiKeyManagementUrl, undefined);
  assert.equal(provider.config.api?.headers, undefined);
  // 非凭据字段保留：入口开关与模型展示元数据。
  assert.equal(config.enabled, true);
  assert.equal(provider.config.api?.baseUrl, "https://offpeak.example");
});

test("redactOffPeakClientConfig keeps credential-free configs on the same reference", () => {
  const clean = {
    enabled: false,
    modelSelectionView: { revision: 1, providers: [{ providerId: "p", config: { api: { type: "openai" } } }] },
  } as unknown as OffPeakClientConfig;
  assert.strictEqual(redactOffPeakClientConfig(clean), clean);
});

test("read-only coding-plan-subscription service rejects every payment-flow method without touching the device service", () => {
  const fake = createFakeCodingPlanSubscriptionService();
  const wrapped = createReadOnlyCodingPlanSubscriptionService(fake);
  const rejections: Array<() => unknown> = [
    () => wrapped.createSign(null as never),
    () => wrapped.updateSign(null as never),
    () => wrapped.checkPayment(null as never),
    () => wrapped.checkPendingOrders(null as never),
    () => wrapped.queryStripeCards(null as never),
    () => wrapped.bindStripeCard(null as never),
    () => wrapped.unbindStripeCard(null as never),
    () => wrapped.payStripe(null as never),
    () => wrapped.checkPaypalSupport(null as never),
    () => wrapped.createPaypalSetupToken(null as never),
    () => wrapped.subscribePaypal(null as never),
    () => wrapped.createEnterpriseOrder(null as never),
    () => wrapped.cancelEnterpriseOrder(null as never),
    () => wrapped.continueEnterpriseOrderPayment(null as never),
  ];
  for (const attempt of rejections) {
    assert.throws(
      attempt,
      /coding-plan-subscription\.\w+ is not available on the remote bridge \(read-only channel\)/,
    );
  }
  assert.deepEqual(fake.calls, [], "payment flows must not reach the device service");
});

test("coding-plan-subscription read errors are sanitized (no device stack)", async () => {
  const fake = createFakeCodingPlanSubscriptionService();
  const leaky = new Error("subscription vendor 5xx");
  leaky.stack = "Error: subscription vendor 5xx\n    at /Users/device/zcode/out/host/...";
  fake.getStaticProducts = async () => {
    throw leaky;
  };
  const wrapped = createReadOnlyCodingPlanSubscriptionService(fake);

  const caught = await wrapped.getStaticProducts().then(
    () => null,
    (error: unknown) => error,
  );
  assert.ok(caught instanceof Error);
  assert.equal(caught.message, "subscription vendor 5xx");
  assert.equal(caught.stack, undefined);
});

// ── window-controller：raw 暴露、7 接口成员全放行、生命周期钩子不出网 ────────

test("window-controller rpc surface keeps all 8 interface members and strips the device-side dispose hook", () => {
  let disposed = 0;
  const attachment = {
    listTaskList: async () => ({ items: [], total: 0, hasMore: false }),
    subscribeControllerV4: async () => ({ ack: { subscriptionId: "s1", logEpoch: 1, seq: 0 } }),
    resyncControllerV4: async () => ({ ack: { subscriptionId: "s1", logEpoch: 1, seq: 0 } }),
    unsubscribeControllerV4: async () => {},
    onDynamicControllerFrame: () => () => ({ dispose() {} }),
    mutateTask: async () => null,
    deleteArchivedTask: async () => true,
    deleteArchivedTasks: async () => ({ deletedTaskIds: [], skippedTaskIds: [], failedTaskIds: [] }),
    dispose: () => {
      disposed += 1;
    },
  } as unknown as IWindowControllerService & { dispose(): void };
  const rpcSurface = createWindowControllerRpcSurface(attachment) as unknown as Record<
    string,
    unknown
  >;
  for (const member of [
    "listTaskList",
    "subscribeControllerV4",
    "resyncControllerV4",
    "unsubscribeControllerV4",
    "onDynamicControllerFrame",
    "mutateTask",
    "deleteArchivedTask",
    "deleteArchivedTasks",
  ]) {
    assert.equal(typeof rpcSurface[member], "function", `rpc surface must expose ${member}`);
  }
  // dispose 是设备侧生命周期钩子（挂连接清理），绝不出现在 RPC 面上。
  assert.equal("dispose" in rpcSurface, false);
  assert.equal(rpcSurface.dispose, undefined);
  assert.equal(disposed, 0);
});

// ── 供应商侧读限频 + 缓存击穿旗标剥离（security review minor）────────────────

test("usage-stats reads are rate limited per wrapper instance and replay the last snapshot", async () => {
  const fake = createFakeUsageStatsService();
  let underlyingCalls = 0;
  fake.getSnapshot = async () => {
    underlyingCalls += 1;
    return { range: "7d", generatedAt: underlyingCalls } as never;
  };
  const wrapped = createReadOnlyUsageStatsService(fake);

  const results = [];
  for (let index = 0; index < 8; index += 1) {
    results.push(await wrapped.getSnapshot({ range: "7d" }));
  }
  // 60s 窗口内最多 6 次真实读；第 7 次起回放最近一次成功值（引用相同）。
  assert.equal(underlyingCalls, 6);
  assert.strictEqual(results[6], results[5]);
  assert.strictEqual(results[7], results[5]);
});

test("usage-stats rate limited reads without any successful snapshot fail with a clear error", async () => {
  const fake = createFakeUsageStatsService();
  fake.getSnapshot = async () => {
    throw new Error("vendor monitor down");
  };
  const wrapped = createReadOnlyUsageStatsService(fake);

  for (let index = 0; index < 6; index += 1) {
    await assert.rejects(wrapped.getSnapshot({ range: "7d" }), /vendor monitor down/);
  }
  // 连一次成功快照都没有时不能回放假数据：抛明确的限频错误。
  await assert.rejects(
    wrapped.getSnapshot({ range: "7d" }),
    /usage-stats\.getSnapshot is rate limited on the remote bridge/,
  );
});

test("usage-stats wrapper strips invalidateBalanceCache from entitlement requests", async () => {
  const fake = createFakeUsageStatsService();
  const seen: Array<Record<string, unknown> | undefined> = [];
  fake.getEntitlementSnapshot = async (request) => {
    seen.push(request as Record<string, unknown> | undefined);
    return { authenticated: true } as never;
  };
  const wrapped = createReadOnlyUsageStatsService(fake);

  await wrapped.getEntitlementSnapshot({ invalidateBalanceCache: true, includeSubscription: true });
  const clean = { includeSubscription: true };
  await wrapped.getEntitlementSnapshot(clean);

  // 击穿缓存的旗标剥掉；其余请求字段保留；无旗标请求原引用直通（不无辜拷贝）。
  assert.equal(seen[0]?.invalidateBalanceCache, undefined);
  assert.equal(seen[0]?.includeSubscription, true);
  assert.strictEqual(seen[1], clean);
});

test("subscription client-config reads drop forceRefresh before reaching the device service", async () => {
  const fake = createFakeCodingPlanSubscriptionService();
  const seen: Array<{ forceRefresh?: boolean } | undefined> = [];
  fake.getOffPeakClientConfig = async (options) => {
    seen.push(options);
    return { enabled: true, modelSelectionView: { revision: 1, providers: [] } };
  };
  fake.getDynamicWorkflowClientConfig = async (options) => {
    seen.push(options);
    return { mode: "disabled", enabled: false, source: "default" };
  };
  const wrapped = createReadOnlyCodingPlanSubscriptionService(fake);

  const cleanOptions = { forceRefresh: false };
  await wrapped.getOffPeakClientConfig({ forceRefresh: true });
  await wrapped.getDynamicWorkflowClientConfig({ forceRefresh: true });
  await wrapped.getDynamicWorkflowClientConfig(cleanOptions);

  assert.equal(seen[0]?.forceRefresh, undefined);
  assert.equal(seen[1]?.forceRefresh, undefined);
  assert.strictEqual(seen[2], cleanOptions);
});

test("subscription vendor reads are rate limited while the constant strategy read stays unlimited", async () => {
  const fake = createFakeCodingPlanSubscriptionService();
  let previewCalls = 0;
  let strategyCalls = 0;
  fake.preview = async () => {
    previewCalls += 1;
    return { productId: "p1", bizId: "b1" };
  };
  fake.getModelContextBudgetStrategy = async () => {
    strategyCalls += 1;
    return "preflight-v1";
  };
  const wrapped = createReadOnlyCodingPlanSubscriptionService(fake);

  const previews = [];
  for (let index = 0; index < 8; index += 1) {
    previews.push(await wrapped.preview(null as never));
  }
  // getModelContextBudgetStrategy 是固定常量（不打网络/供应商），不进限频窗口。
  for (let index = 0; index < 10; index += 1) {
    await wrapped.getModelContextBudgetStrategy();
  }
  assert.equal(previewCalls, 6);
  assert.strictEqual(previews[6], previews[5]);
  assert.equal(strategyCalls, 10);
});

test("subscription offpeak replay after rate limit stays credential-redacted", async () => {
  const fake = createFakeCodingPlanSubscriptionService();
  const wrapped = createReadOnlyCodingPlanSubscriptionService(fake);

  const configs = [];
  for (let index = 0; index < 8; index += 1) {
    configs.push(await wrapped.getOffPeakClientConfig());
  }
  assert.equal(
    fake.calls.filter((name) => name === "getOffPeakClientConfig").length,
    6,
    "7th+ calls replay the 6th snapshot instead of hitting the device service",
  );
  // 回放缓存存的是包装层返回值：限频重放的 offpeak 配置同样剥掉 apiKey/headers。
  const replayed = configs[7]!;
  const provider = replayed.modelSelectionView.providers[0] as unknown as {
    config: { access?: Record<string, unknown>; api?: Record<string, unknown> };
  };
  assert.equal(provider.config.access?.apiKey, undefined);
  assert.equal(provider.config.api?.headers, undefined);
});

// ── 连接资源生命周期：window-controller attachment 随 teardown 收口（两分支）──

test("bridge connection resources dispose attachments and scopes on teardown in both connection branches", async () => {
  // 分支形态一（有 current connection 的 teardown）：注册期填入 2 个 attachment +
  // 1 个 agent scope，disposeAll 全部收口；单个 dispose 抛错不阻塞其余成员。
  const resources = createRemoteBridgeConnectionResources();
  const disposed: string[] = [];
  resources.windowControllerAttachments.push(
    { dispose: () => void disposed.push("attachment-1") },
    {
      dispose: () => {
        throw new Error("dispose boom");
      },
    },
    { dispose: () => void disposed.push("attachment-3") },
  );
  resources.agentScopes.push({ dispose: async () => void disposed.push("scope-1") });

  await resources.disposeAll();
  assert.deepEqual(disposed, ["scope-1", "attachment-1", "attachment-3"]);

  // 分支形态二（无 current connection：连接从未建立或已收口后的重复 teardown）：
  // 簿本已清空，幂等收口不抛错、不重复 dispose。
  await resources.disposeAll();
  assert.equal(disposed.length, 3);
});

// ── 注册结构：brand、结构化裁决、raw 直注册 fail ────────────────────────────

test("only wrapper factories produce redacted-branded instances (raw services are rejected by the brand check)", () => {
  const fakeOAuth = createFakeOAuthService();
  const fakeSettings = createFakeProviderSettingsService(buildProviderSettingsView());
  const fakeCredential = createFakeCredentialService();
  const fakeUsageStats = createFakeUsageStatsService();
  const fakeSubscription = createFakeCodingPlanSubscriptionService();
  assert.equal(isRemoteBridgeRedactedService(fakeOAuth), false);
  assert.equal(isRemoteBridgeRedactedService(fakeSettings), false);
  assert.equal(isRemoteBridgeRedactedService(fakeCredential), false);
  assert.equal(isRemoteBridgeRedactedService(fakeUsageStats), false);
  assert.equal(isRemoteBridgeRedactedService(fakeSubscription), false);
  assert.equal(isRemoteBridgeRedactedService(createReadOnlyOAuthService(fakeOAuth)), true);
  assert.equal(
    isRemoteBridgeRedactedService(createRedactedProviderSettingsService(fakeSettings)),
    true,
  );
  assert.equal(
    isRemoteBridgeRedactedService(createReadOnlyCredentialService(fakeCredential)),
    true,
  );
  assert.equal(isRemoteBridgeRedactedService(createReadOnlyUsageStatsService(fakeUsageStats)), true);
  assert.equal(
    isRemoteBridgeRedactedService(createReadOnlyCodingPlanSubscriptionService(fakeSubscription)),
    true,
  );
});

test("registerRedactedChannel refuses raw service instances at the registration entry", () => {
  const registered: string[] = [];
  const server = {
    registerChannel: (name: string) => registered.push(name),
  } as unknown as ChannelServer;
  const fakeSettings = createFakeProviderSettingsService(buildProviderSettingsView());
  assert.throws(
    () => registerRedactedChannel(server, "provider-settings", fakeSettings),
    /must be registered through its redaction wrapper/,
  );
  registerRedactedChannel(
    server,
    "provider-settings",
    createRedactedProviderSettingsService(fakeSettings),
  );
  assert.deepEqual(registered, ["provider-settings"]);
});

test("every bridge whitelist channel has an explicit wrapped/raw ruling (structural assertion)", () => {
  const rulings: Record<string, string> = {};
  for (const descriptor of REMOTE_BRIDGE_SERVICE_WHITELIST) {
    const ruling = resolveRemoteBridgeChannelRuling(descriptor.channelName);
    assert.notEqual(ruling, "unruled", `${descriptor.channelName} must be ruled wrapped or raw`);
    assert.notEqual(ruling, "forbidden", `${descriptor.channelName} must not be forbidden`);
    rulings[descriptor.channelName] = ruling;
  }
  // 凭据邻接通道裁决：provisioning-target 禁；oauth/provider-settings/credential/
  // usage-stats/coding-plan-subscription 只许 wrapped；window-controller 与 zcode-agent
  // 同级信任（用户内容面），raw 放行。
  assert.equal(resolveRemoteBridgeChannelRuling("provider-provisioning-target"), "forbidden");
  assert.equal(resolveRemoteBridgeChannelRuling(IOAuthService.channelName), "wrapped");
  assert.equal(resolveRemoteBridgeChannelRuling(IProviderSettingsService.channelName), "wrapped");
  assert.equal(resolveRemoteBridgeChannelRuling(ICredentialService.channelName), "wrapped");
  assert.equal(resolveRemoteBridgeChannelRuling(IUsageStatsService.channelName), "wrapped");
  assert.equal(
    resolveRemoteBridgeChannelRuling(ICodingPlanSubscriptionService.channelName),
    "wrapped",
  );
  assert.equal(resolveRemoteBridgeChannelRuling(IWindowControllerService.channelName), "raw");
  assert.equal(resolveRemoteBridgeChannelRuling("model-selection"), "wrapped");
  assert.equal(rulings["oauth"], "wrapped");
  assert.equal(rulings["provider-settings"], "wrapped");
  assert.equal(rulings["credential"], "wrapped");
  assert.equal(rulings["usage-stats"], "wrapped");
  assert.equal(rulings["coding-plan-subscription"], "wrapped");
  assert.equal(rulings["window-controller"], "raw");
  assert.equal(rulings["setting"], "raw");
  assert.equal(resolveRemoteBridgeChannelRuling("git"), "unruled");
  // 原版 UI 按 channel name 取服务：包装注册必须落在同名通道上。
  assert.equal(IOAuthService.channelName, "oauth");
  assert.equal(IProviderSettingsService.channelName, "provider-settings");
  assert.equal(ICredentialService.channelName, "credential");
  assert.equal(IUsageStatsService.channelName, "usage-stats");
  assert.equal(ICodingPlanSubscriptionService.channelName, "coding-plan-subscription");
  assert.equal(IWindowControllerService.channelName, "window-controller");
});

// ── relay：方法级第二道墙与两侧镜像 ──────────────────────────────────────────

test("relay keeps provider-provisioning-target forbidden and proxies the five wrapped channels plus raw window-controller", () => {
  const whitelist = DEFAULT_RELAY_DEVICE_SERVICE_WHITELIST.map((d) => d.channelName);
  const forbidden = RELAY_FORBIDDEN_DEVICE_SERVICES.map((d) => d.channelName);
  assert.equal(whitelist.includes("oauth"), true);
  assert.equal(whitelist.includes("provider-settings"), true);
  assert.equal(whitelist.includes("credential"), true);
  assert.equal(whitelist.includes("usage-stats"), true);
  assert.equal(whitelist.includes("coding-plan-subscription"), true);
  // window-controller 走无方法墙的透明转发（用户内容面，与 zcode-agent 同级信任）。
  assert.equal(whitelist.includes("window-controller"), true);
  assert.equal(
    Object.prototype.hasOwnProperty.call(RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS, "window-controller"),
    false,
    "window-controller is raw on the relay; it must not appear behind the read-only wall",
  );
  assert.deepEqual(forbidden, ["provider-provisioning-target"]);
  for (const name of forbidden) {
    assert.equal(whitelist.includes(name), false, `relay whitelist must not include ${name}`);
  }
});

test("relay read-only method wall mirrors the device-side wrapper read surface", () => {
  // oauth：relay 放行方法 = 设备包装的 dry 读面；restoreSession/peek 是设备内部原语，两侧都不放。
  assert.deepEqual([...RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS["oauth"]!].sort(), [
    "getActiveProvider",
    "getProviders",
    "restoreCachedSession",
    "restoreCachedSessionState",
  ]);
  assert.deepEqual([...RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS["provider-settings"]!].sort(), [
    "getView",
    "onDidChange",
    "refresh",
  ]);
  // credential：relay 只放 load（键策略在设备侧包装内裁决，relay 不重复键级逻辑）。
  assert.deepEqual([...RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS["credential"]!], ["load"]);
  // usage-stats：5 个统计读；重置动作（use/requestOpportunity/markHistoryRead）两侧都不放。
  assert.deepEqual([...RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS["usage-stats"]!].sort(), [
    "getAppUsageSnapshot",
    "getCodingPlanResetStatus",
    "getCodingPlanUsageSnapshot",
    "getEntitlementSnapshot",
    "getSnapshot",
  ]);
  // coding-plan-subscription：15 个目录/定价/订单状态读；支付流两侧都拒。
  assert.deepEqual(
    [...RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS["coding-plan-subscription"]!].sort(),
    [
      "batchPreview",
      "calculateEnterpriseOrder",
      "checkEnterpriseOrderStatus",
      "getDynamicWorkflowClientConfig",
      "getEnterpriseBalance",
      "getEnterprisePendingOrders",
      "getEnterprisePricing",
      "getForceUpdateConfig",
      "getModelContextBudgetStrategy",
      "getOffPeakClientConfig",
      "getStartPlanPreview",
      "getStaticProducts",
      "getStaticTeamProducts",
      "preview",
      "productInfo",
    ],
  );
  // 镜像的每个方法在设备包装上必须是真实存在的函数成员。
  const oauth = createReadOnlyOAuthService(createFakeOAuthService()) as unknown as Record<
    string,
    unknown
  >;
  for (const method of RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS["oauth"]!) {
    assert.equal(typeof oauth[method], "function", `oauth wrapper must expose ${method}`);
  }
  const settings = createRedactedProviderSettingsService(
    createFakeProviderSettingsService(buildProviderSettingsView()),
  ) as unknown as Record<string, unknown>;
  for (const method of RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS["provider-settings"]!) {
    assert.equal(
      typeof settings[method],
      "function",
      `provider-settings wrapper must expose ${method}`,
    );
  }
  const credential = createReadOnlyCredentialService(
    createFakeCredentialService(),
  ) as unknown as Record<string, unknown>;
  for (const method of RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS["credential"]!) {
    assert.equal(typeof credential[method], "function", `credential wrapper must expose ${method}`);
  }
  const usageStats = createReadOnlyUsageStatsService(
    createFakeUsageStatsService(),
  ) as unknown as Record<string, unknown>;
  for (const method of RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS["usage-stats"]!) {
    assert.equal(typeof usageStats[method], "function", `usage-stats wrapper must expose ${method}`);
  }
  const subscription = createReadOnlyCodingPlanSubscriptionService(
    createFakeCodingPlanSubscriptionService(),
  ) as unknown as Record<string, unknown>;
  for (const method of RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS["coding-plan-subscription"]!) {
    assert.equal(
      typeof subscription[method],
      "function",
      `coding-plan-subscription wrapper must expose ${method}`,
    );
  }
});
