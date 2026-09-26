import assert from "node:assert/strict";
import test from "node:test";
import { ProxyChannel, type IChannel } from "@zcode/rpc";
import {
  createRelayReadOnlyDeviceService,
  DEFAULT_RELAY_DEVICE_SERVICE_WHITELIST,
  RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS,
} from "../src/relay.js";

/**
 * 方法级第二道墙（security review Major 1）：冒充主机可在设备侧注册 raw 服务，
 * 但网页客户端只经 relay 取这三条通道——成员表外的调用必须在 relay 的
 * ChannelServer（ProxyChannel.fromService.call）被拒，且绝不转发给主机。
 */

interface RecordingChannel {
  channel: IChannel;
  forwardedCalls: string[];
  listenedEvents: string[];
}

function createRecordingChannel(responses: Record<string, unknown> = {}): RecordingChannel {
  const forwardedCalls: string[] = [];
  const listenedEvents: string[] = [];
  const channel: IChannel = {
    call: (command: string) => {
      forwardedCalls.push(command);
      const response = responses[command];
      if (response instanceof Error) {
        return Promise.reject(response);
      }
      return Promise.resolve(response ?? null);
    },
    listen: (event: string) => {
      listenedEvents.push(event);
      return () => ({ dispose() {} });
    },
  };
  return { channel, forwardedCalls, listenedEvents };
}

test("provider-settings wall forwards reads and blocks every mutation at the relay", async () => {
  const recording = createRecordingChannel({ getView: { revision: 1, providers: [] } });
  const filtered = createRelayReadOnlyDeviceService<object>(recording.channel, "provider-settings");
  // 复刻 relay attach 的服务端暴露形状：ServiceCollection.exposeOnChannelServer 走
  // ProxyChannel.fromService，非成员方法在这里就是 Method not found（ChannelServer
  // 的 onPromise 会把同步 throw 转成错误响应，这里直接断言 throw）。
  const serverChannel = ProxyChannel.fromService(filtered);

  assert.deepEqual(await serverChannel.call("ctx", "getView"), { revision: 1, providers: [] });
  const event = serverChannel.listen("ctx", "onDidChange");
  assert.equal(typeof event, "function");
  event(() => {});
  assert.deepEqual(recording.listenedEvents, ["onDidChange"]);

  const blocked = [
    "savePersonalProviderOverlay",
    "createPersonalProvider",
    "testModelConnectivity",
  ];
  for (const method of blocked) {
    assert.throws(
      () => serverChannel.call("ctx", method, ["p", {}]),
      /Method not found/,
      `${method} must be rejected at the relay`,
    );
  }
  assert.deepEqual(recording.forwardedCalls, ["getView"], "mutations must never reach the host");
});

test("oauth wall forwards dry reads and blocks flows/mutations at the relay", async () => {
  const recording = createRecordingChannel({
    getActiveProvider: "zai",
    restoreCachedSessionState: { status: "signed-out" },
  });
  const filtered = createRelayReadOnlyDeviceService<object>(recording.channel, "oauth");
  const serverChannel = ProxyChannel.fromService(filtered);

  assert.equal(await serverChannel.call("ctx", "getActiveProvider"), "zai");
  assert.deepEqual(await serverChannel.call("ctx", "restoreCachedSessionState"), {
    status: "signed-out",
  });

  // 冒充主机的收割面：authorizeUrl 钓鱼（startOAuthWithPolling）与录 key
  // （handleCallback/refreshToken/logout）都必须在 relay 拒绝。
  const blocked = [
    "startOAuth",
    "startOAuthWithPolling",
    "pollPendingOAuth",
    "handleCallback",
    "refreshToken",
    "logout",
    "logoutAll",
    "cancelPending",
    "restoreSession",
    "peekCachedSessionState",
  ];
  for (const method of blocked) {
    assert.throws(
      () => serverChannel.call("ctx", method),
      /Method not found/,
      `${method} must be rejected at the relay`,
    );
  }
  assert.deepEqual(recording.forwardedCalls, ["getActiveProvider", "restoreCachedSessionState"]);
});

test("credential wall forwards load only and blocks save/delete at the relay", async () => {
  const recording = createRecordingChannel({ load: "redacted-present" });
  const filtered = createRelayReadOnlyDeviceService<object>(recording.channel, "credential");
  const serverChannel = ProxyChannel.fromService(filtered);

  // 只放 load：键策略（原值/占位/拒绝）在设备侧包装内裁决，relay 不重复键级逻辑。
  assert.equal(
    await serverChannel.call("ctx", "load", ["oauth:active_provider"]),
    "redacted-present",
  );
  // 冒充主机的收割面：credential.save/delete（录任意键值/清库）必须在 relay 拒绝。
  for (const method of ["save", "delete"]) {
    assert.throws(
      () => serverChannel.call("ctx", method, ["oauth:zai:access_token", "captured"]),
      /Method not found/,
      `${method} must be rejected at the relay`,
    );
  }
  assert.deepEqual(recording.forwardedCalls, ["load"], "writes must never reach the host");
});

test("usage-stats wall forwards stat reads and blocks vendor reset actions at the relay", async () => {
  const recording = createRecordingChannel({
    getSnapshot: { range: "7d", summary: { totalSessions: 2 } },
    getEntitlementSnapshot: { authenticated: true },
  });
  const filtered = createRelayReadOnlyDeviceService<object>(recording.channel, "usage-stats");
  const serverChannel = ProxyChannel.fromService(filtered);

  assert.deepEqual(await serverChannel.call("ctx", "getSnapshot", [{ range: "7d" }]), {
    range: "7d",
    summary: { totalSessions: 2 },
  });
  assert.deepEqual(await serverChannel.call("ctx", "getEntitlementSnapshot"), {
    authenticated: true,
  });

  // 供应商侧重置动作（use/requestOpportunity/markHistoryRead）在 relay 即拒绝。
  const blocked = ["useCodingPlanReset", "requestCodingPlanResetOpportunity", "markCodingPlanResetHistoryRead"];
  for (const method of blocked) {
    assert.throws(
      () => serverChannel.call("ctx", method, [null]),
      /Method not found/,
      `${method} must be rejected at the relay`,
    );
  }
  assert.deepEqual(recording.forwardedCalls, ["getSnapshot", "getEntitlementSnapshot"]);
});

test("coding-plan-subscription wall forwards catalog reads and blocks every payment flow at the relay", async () => {
  const recording = createRecordingChannel({
    batchPreview: { productList: [], isSubscribed: false, isAuthenticated: true },
    getOffPeakClientConfig: { enabled: true },
    preview: { productId: "p1", bizId: "b1" },
  });
  const filtered = createRelayReadOnlyDeviceService<object>(
    recording.channel,
    "coding-plan-subscription",
  );
  const serverChannel = ProxyChannel.fromService(filtered);

  assert.equal((await serverChannel.call("ctx", "batchPreview", [null])).isAuthenticated, true);
  assert.deepEqual(await serverChannel.call("ctx", "getOffPeakClientConfig", [null]), {
    enabled: true,
  });
  assert.equal((await serverChannel.call("ctx", "preview", [null])).bizId, "b1");

  // 冒充主机的支付收割面：签约/扣款/绑卡/paypal/企业下单续付全部在 relay 拒绝。
  const blocked = [
    "createSign",
    "updateSign",
    "checkPayment",
    "checkPendingOrders",
    "queryStripeCards",
    "bindStripeCard",
    "unbindStripeCard",
    "payStripe",
    "checkPaypalSupport",
    "createPaypalSetupToken",
    "subscribePaypal",
    "createEnterpriseOrder",
    "cancelEnterpriseOrder",
    "continueEnterpriseOrderPayment",
  ];
  for (const method of blocked) {
    assert.throws(
      () => serverChannel.call("ctx", method, [null]),
      /Method not found/,
      `${method} must be rejected at the relay`,
    );
  }
  assert.deepEqual(recording.forwardedCalls, [
    "batchPreview",
    "getOffPeakClientConfig",
    "preview",
  ]);
});

test("read-only wall covers exactly the five wrapped channels in the relay whitelist", () => {
  const wallChannels = Object.keys(RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS).sort();
  assert.deepEqual(wallChannels, [
    "coding-plan-subscription",
    "credential",
    "oauth",
    "provider-settings",
    "usage-stats",
  ]);
  for (const channelName of wallChannels) {
    assert.equal(
      DEFAULT_RELAY_DEVICE_SERVICE_WHITELIST.some((d) => d.channelName === channelName),
      true,
      `${channelName} must stay in the relay whitelist or the wall is dead code`,
    );
    assert.ok(
      (RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS[channelName] ?? []).length > 0,
      `${channelName} must declare at least one allowed read method`,
    );
  }
  // window-controller 是无方法墙的 raw 透明转发成员：必须在挂载白名单内、且不在墙后。
  assert.equal(
    DEFAULT_RELAY_DEVICE_SERVICE_WHITELIST.some((d) => d.channelName === "window-controller"),
    true,
    "window-controller must stay in the relay whitelist for conversation workspace task lists",
  );
  assert.equal(
    wallChannels.includes("window-controller"),
    false,
    "window-controller must not sit behind the read-only wall",
  );
});
