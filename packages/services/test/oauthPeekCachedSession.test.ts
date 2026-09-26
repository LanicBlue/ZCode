import assert from "node:assert/strict";
import test from "node:test";
import { CREDENTIAL_DECRYPT_ERROR_CODE } from "@zcode/shared";
import { OAuthService } from "../src/oauth/oauthService.js";
import type { ICredentialService } from "../src/credential/credential.js";

/**
 * peekCachedSessionState 的观察语义（security review Major 2）：
 * 任何输入分支都不触发写（save/delete/clearActiveSession）——远控桥经它 dry 合成
 * 登录展示态，不得因 web 一次读取破坏设备登录态。
 */

type Operation = { kind: "save" | "delete"; key: string; value?: string };

function createRecordingCredentialStore(entries: Record<string, string | Error>): {
  credentialService: ICredentialService;
  operations: Operation[];
} {
  const operations: Operation[] = [];
  const credentialService = {
    async load(key: string): Promise<string | null> {
      const entry = entries[key];
      if (entry instanceof Error) {
        throw entry;
      }
      return entry ?? null;
    },
    async save(key: string, value: string): Promise<void> {
      operations.push({ kind: "save", key, value });
      entries[key] = value;
    },
    async delete(key: string): Promise<void> {
      operations.push({ kind: "delete", key });
      delete entries[key];
    },
  } as unknown as ICredentialService;
  return { credentialService, operations };
}

function decryptError(): Error {
  const error = new Error("凭据解密失败：test");
  (error as Error & { code?: unknown }).code = CREDENTIAL_DECRYPT_ERROR_CODE;
  return error;
}

function createService(credentialService: ICredentialService): OAuthService {
  // apiClient 是 adapter 构造的必填依赖；peek 是纯读，永远不会触达它，给个必然失败的桩。
  const neverApiClient = {
    async request(): Promise<Response> {
      throw new Error("network access must not happen in peekCachedSessionState");
    },
  };
  return new OAuthService(credentialService, {
    apiClient: neverApiClient,
  });
}

test("peekCachedSessionState returns authenticated display state from cached profile", async () => {
  const { credentialService, operations } = createRecordingCredentialStore({
    "oauth:active_provider": "zai",
    "oauth:zai:user_info": JSON.stringify({
      id: "u1",
      username: "alice",
      displayName: "Alice",
    }),
    zcodejwttoken: "header.payload.signature",
  });
  const service = createService(credentialService);

  const state = await service.peekCachedSessionState();
  assert.equal(state.status, "authenticated");
  if (state.status !== "authenticated") return;
  assert.deepEqual(state.userInfo, { id: "u1", username: "alice", displayName: "Alice" });
  assert.deepEqual(operations, [], "peek must not write credentials");
});

test("peekCachedSessionState maps missing active provider / profile to signed-out", async () => {
  const noProvider = createRecordingCredentialStore({});
  assert.deepEqual(await createService(noProvider.credentialService).peekCachedSessionState(), {
    status: "signed-out",
  });

  const noProfile = createRecordingCredentialStore({ "oauth:active_provider": "zai" });
  assert.deepEqual(await createService(noProfile.credentialService).peekCachedSessionState(), {
    status: "signed-out",
  });
  assert.deepEqual(noProfile.operations, []);
});

test("peekCachedSessionState keeps corrupt (undecryptable) sessions intact instead of clearing them", async () => {
  const { credentialService, operations } = createRecordingCredentialStore({
    "oauth:active_provider": decryptError(),
    "oauth:zai:user_info": decryptError(),
    zcodejwttoken: decryptError(),
  });
  const service = createService(credentialService);

  assert.deepEqual(await service.peekCachedSessionState(), { status: "signed-out" });
  assert.deepEqual(
    operations,
    [],
    "peek must not run clearCorruptOAuthSession (destructive on corrupt data)",
  );
});

test("peekCachedSessionState maps missing zcode JWT (zai) to signed-out without cleanup", async () => {
  const { credentialService, operations } = createRecordingCredentialStore({
    "oauth:active_provider": "zai",
    "oauth:zai:user_info": JSON.stringify({
      id: "u1",
      username: "alice",
      displayName: "Alice",
    }),
  });
  const service = createService(credentialService);

  assert.deepEqual(await service.peekCachedSessionState(), { status: "signed-out" });
  assert.deepEqual(operations, []);
});

test("peekCachedSessionState maps expired zcode JWT to signed-out without cleanup", async () => {
  // payload = base64url({"exp":1})：resolveJwtExpiration 判定 expired。
  const expiredPayload = Buffer.from(JSON.stringify({ exp: 1 }))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const { credentialService, operations } = createRecordingCredentialStore({
    "oauth:active_provider": "zai",
    "oauth:zai:user_info": JSON.stringify({
      id: "u1",
      username: "alice",
      displayName: "Alice",
    }),
    zcodejwttoken: `header.${expiredPayload}.signature`,
  });
  const service = createService(credentialService);

  // 观察视角：设备端 restore 会清理过期会话；peek 只按未登录展示，不代为清理。
  assert.deepEqual(await service.peekCachedSessionState(), { status: "signed-out" });
  assert.deepEqual(operations, []);
});
