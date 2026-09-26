import assert from "node:assert/strict";
import test from "node:test";
import {
  REMOTE_BRIDGE_CREDENTIAL_PRESENT_PLACEHOLDER,
  REMOTE_BRIDGE_SERVICE_WHITELIST,
  createReadOnlyCredentialService,
  createReadOnlyOAuthService,
  createRedactedProviderSettingsService,
  isRemoteBridgeRedactedService,
  redactProviderSettingsView,
  registerRedactedChannel,
  resolveRemoteBridgeChannelRuling,
  resolveRemoteBridgeCredentialKeyRuling,
} from "../src/host/remoteBridge.js";
import {
  ICredentialService,
  IOAuthService,
  IProviderSettingsService,
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

// ── 注册结构：brand、结构化裁决、raw 直注册 fail ────────────────────────────

test("only wrapper factories produce redacted-branded instances (raw services are rejected by the brand check)", () => {
  const fakeOAuth = createFakeOAuthService();
  const fakeSettings = createFakeProviderSettingsService(buildProviderSettingsView());
  const fakeCredential = createFakeCredentialService();
  assert.equal(isRemoteBridgeRedactedService(fakeOAuth), false);
  assert.equal(isRemoteBridgeRedactedService(fakeSettings), false);
  assert.equal(isRemoteBridgeRedactedService(fakeCredential), false);
  assert.equal(isRemoteBridgeRedactedService(createReadOnlyOAuthService(fakeOAuth)), true);
  assert.equal(
    isRemoteBridgeRedactedService(createRedactedProviderSettingsService(fakeSettings)),
    true,
  );
  assert.equal(
    isRemoteBridgeRedactedService(createReadOnlyCredentialService(fakeCredential)),
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
  // 凭据邻接通道裁决：provisioning-target 禁；oauth/provider-settings/credential 只许 wrapped。
  assert.equal(resolveRemoteBridgeChannelRuling("provider-provisioning-target"), "forbidden");
  assert.equal(resolveRemoteBridgeChannelRuling(IOAuthService.channelName), "wrapped");
  assert.equal(resolveRemoteBridgeChannelRuling(IProviderSettingsService.channelName), "wrapped");
  assert.equal(resolveRemoteBridgeChannelRuling(ICredentialService.channelName), "wrapped");
  assert.equal(resolveRemoteBridgeChannelRuling("model-selection"), "wrapped");
  assert.equal(rulings["oauth"], "wrapped");
  assert.equal(rulings["provider-settings"], "wrapped");
  assert.equal(rulings["credential"], "wrapped");
  assert.equal(rulings["setting"], "raw");
  assert.equal(resolveRemoteBridgeChannelRuling("git"), "unruled");
  // 原版 UI 按 channel name 取服务：包装注册必须落在同名通道上。
  assert.equal(IOAuthService.channelName, "oauth");
  assert.equal(IProviderSettingsService.channelName, "provider-settings");
  assert.equal(ICredentialService.channelName, "credential");
});

// ── relay：方法级第二道墙与两侧镜像 ──────────────────────────────────────────

test("relay keeps provider-provisioning-target forbidden and proxies the three wrapped channels", () => {
  const whitelist = DEFAULT_RELAY_DEVICE_SERVICE_WHITELIST.map((d) => d.channelName);
  const forbidden = RELAY_FORBIDDEN_DEVICE_SERVICES.map((d) => d.channelName);
  assert.equal(whitelist.includes("oauth"), true);
  assert.equal(whitelist.includes("provider-settings"), true);
  assert.equal(whitelist.includes("credential"), true);
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
});
