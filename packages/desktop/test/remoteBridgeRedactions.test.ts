import assert from "node:assert/strict";
import test from "node:test";
import {
  REMOTE_BRIDGE_SERVICE_WHITELIST,
  createReadOnlyOAuthService,
  createRedactedProviderSettingsService,
  isRemoteBridgeRedactedService,
  redactProviderSettingsView,
} from "../src/host/remoteBridge.js";
import {
  IOAuthService,
  IProviderSettingsService,
  type ProviderSettingsView,
} from "@zcode/services";
import {
  DEFAULT_RELAY_DEVICE_SERVICE_WHITELIST,
  RELAY_FORBIDDEN_DEVICE_SERVICES,
} from "@zcode/server";

// ── fakes ───────────────────────────────────────────────────────────────────

function createFakeOAuthService(): IOAuthService & { calls: string[] } {
  const calls: string[] = [];
  const record = <T>(name: string, value: T): T => {
    calls.push(name);
    return value;
  };
  const refuse = (name: string) => async () => {
    throw new Error(`underlying ${name} must not be called on the remote bridge`);
  };
  return {
    calls,
    getProviders: async () =>
      record("getProviders", [{ id: "zai", displayName: "Z.AI", enabled: true, order: 1 }]),
    getActiveProvider: async () => record("getActiveProvider", "zai"),
    restoreCachedSession: async () =>
      record("restoreCachedSession", { id: "u1", username: "alice", displayName: "Alice" }),
    restoreCachedSessionState: async () =>
      record("restoreCachedSessionState", {
        status: "authenticated",
        userInfo: { id: "u1", username: "alice", displayName: "Alice" },
      }),
    restoreSession: async () => record("restoreSession", null),
    startOAuth: refuse("startOAuth"),
    startOAuthWithPolling: refuse("startOAuthWithPolling"),
    pollPendingOAuth: refuse("pollPendingOAuth"),
    handleCallback: refuse("handleCallback"),
    refreshToken: refuse("refreshToken"),
    logout: refuse("logout"),
    logoutAll: refuse("logoutAll"),
    cancelPending: refuse("cancelPending"),
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

function createFakeProviderSettingsService(
  view: ProviderSettingsView,
): IProviderSettingsService & { changeListeners: Array<(view: ProviderSettingsView) => void> } {
  const changeListeners: Array<(view: ProviderSettingsView) => void> = [];
  const refuse = (name: string) => async () => {
    throw new Error(`underlying ${name} must not be called on the remote bridge`);
  };
  return {
    changeListeners,
    getView: async () => view,
    refresh: async () => view,
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

// ── oauth：读侧透传、写侧全拒 ────────────────────────────────────────────────

test("read-only oauth service passes display reads through to the underlying service", async () => {
  const fake = createFakeOAuthService();
  const wrapped = createReadOnlyOAuthService(fake);

  assert.equal(await wrapped.getActiveProvider(), "zai");
  assert.deepEqual(await wrapped.getProviders(), [
    { id: "zai", displayName: "Z.AI", enabled: true, order: 1 },
  ]);
  const user = await wrapped.restoreCachedSession();
  assert.equal(user?.username, "alice");
  const state = await wrapped.restoreCachedSessionState();
  assert.equal(state.status, "authenticated");
  assert.equal(await wrapped.restoreSession(), null);
  assert.deepEqual(fake.calls, [
    "getActiveProvider",
    "getProviders",
    "restoreCachedSession",
    "restoreCachedSessionState",
    "restoreSession",
  ]);
});

test("read-only oauth service rejects every write/flow method without touching the device service", async () => {
  const fake = createFakeOAuthService();
  const wrapped = createReadOnlyOAuthService(fake);
  const rejections: Array<() => unknown> = [
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
});

// ── provider-settings：读侧脱敏、写侧全拒 ────────────────────────────────────

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
  assert.strictEqual(await wrapped.refresh("test"), cleanView);
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

test("redacted provider-settings service rejects every mutation", async () => {
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
  assert.equal(fake.changeListeners.length, 0, "mutations must not reach the underlying service");
});

// ── 注册结构：brand 与双侧名单 ───────────────────────────────────────────────

test("only wrapper factories produce redacted-branded instances (raw services are rejected by the brand check)", () => {
  const fakeOAuth = createFakeOAuthService();
  const fakeSettings = createFakeProviderSettingsService(buildProviderSettingsView());
  assert.equal(isRemoteBridgeRedactedService(fakeOAuth), false);
  assert.equal(isRemoteBridgeRedactedService(fakeSettings), false);
  assert.equal(isRemoteBridgeRedactedService(createReadOnlyOAuthService(fakeOAuth)), true);
  assert.equal(
    isRemoteBridgeRedactedService(createRedactedProviderSettingsService(fakeSettings)),
    true,
  );
});

test("bridge raw whitelist stays free of credential-adjacent and wrapped-only channel names", () => {
  const names = REMOTE_BRIDGE_SERVICE_WHITELIST.map((descriptor) => descriptor.channelName);
  for (const forbidden of [
    "credential",
    "oauth",
    "provider-provisioning-target",
    "provider-settings",
  ]) {
    assert.equal(names.includes(forbidden), false, `raw whitelist must not include ${forbidden}`);
  }
  // 原版 UI 按 channel name 取服务：包装注册必须落在同名通道上。
  assert.equal(IOAuthService.channelName, "oauth");
  assert.equal(IProviderSettingsService.channelName, "provider-settings");
});

test("relay allows the redacted channels device-side and keeps credential channels forbidden", () => {
  const whitelist = DEFAULT_RELAY_DEVICE_SERVICE_WHITELIST.map((d) => d.channelName);
  const forbidden = RELAY_FORBIDDEN_DEVICE_SERVICES.map((d) => d.channelName);
  assert.equal(whitelist.includes("oauth"), true);
  assert.equal(whitelist.includes("provider-settings"), true);
  assert.deepEqual(forbidden, ["credential", "provider-provisioning-target"]);
  for (const name of forbidden) {
    assert.equal(whitelist.includes(name), false, `relay whitelist must not include ${name}`);
  }
});
