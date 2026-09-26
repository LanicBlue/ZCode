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
 * 但网页客户端只经 relay 取这两条通道——成员表外的调用必须在 relay 的
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

test("read-only wall covers exactly the two wrapped channels in the relay whitelist", () => {
  const wallChannels = Object.keys(RELAY_DEVICE_READ_ONLY_CHANNEL_METHODS).sort();
  assert.deepEqual(wallChannels, ["oauth", "provider-settings"]);
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
});
