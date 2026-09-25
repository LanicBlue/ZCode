#!/usr/bin/env node
/**
 * Fork 一键升级流水线（LanicBlue/ZCode，本机自建版专用）。
 *
 * 把手工趟平的升级序列固化：
 *   upstream 同步（可跳过）→ 版本递进（可选）→ 构建桌面+CLI → 注入内容插件
 *   → electron-builder 打包（在 dmg 阶段挂死前收割 .app）→ adhoc 重签
 *   → 安装 CLI（mv 原子换名）+ 安装 /Applications（按 PID 换 app）
 *
 * 坑位对策（都有实证教训，改动前先读）：
 *   - prepare:runtime-assets 会整删重建 glm —— 内容插件注入必须在 build 之后、
 *     bundle --skip-prepare --skip-build 之前，没有中间钩子。
 *   - CLI bundle 嵌 bootstrap/dist —— 改过 zcode-cli 子包的 TS 源码后必须先
 *     tsc 构建对应包再 build CLI。
 *   - electron-builder 的 dmg 阶段会无子进程空转挂死 —— 等 .app + zip 出现即 kill。
 *   - macOS ps 主进程只显示短名 —— 换 /Applications 里的 app 必须按 PID kill，
 *     否则旧进程抱着被删 bundle 继续跑。
 *   - T3 kickstart 是部署动作，默认不做，--kickstart-t3 显式触发。
 *
 * 用法：
 *   node scripts/lanic-upgrade.mjs                       # 全流程：upstream+merge+build+装
 *   node scripts/lanic-upgrade.mjs --no-upstream          # 跳过 upstream 同步（本地改动重建）
 *   node scripts/lanic-upgrade.mjs --bump                 # 假版本递进（3.14.100→.101）
 *   node scripts/lanic-upgrade.mjs --production           # 打 "ZCode" 正式身份（替换官方时用；默认 ZCode Preview）
 *   node scripts/lanic-upgrade.mjs --kickstart-t3         # 尾部重建 T3 server 并 kickstart
 *   可叠加 --no-push / --no-install-app / --no-install-cli
 */

import { execFileSync, spawn } from "node:child_process";
import { existsSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const desktopDir = join(repoRoot, "packages", "desktop");
const cliWorkspace = join(repoRoot, "apps", "zcode-cli");
const contentPluginsRoot = expandHome("~/.local/zcode-content-plugins");
const liveCliDir = expandHome("~/.local/zcode-cli");

const args = new Set(process.argv.slice(2));
const FLAGS = {
  upstream: !args.has("--no-upstream"),
  bump: args.has("--bump"),
  production: args.has("--production"),
  kickstartT3: args.has("--kickstart-t3"),
  push: !args.has("--no-push"),
  installApp: !args.has("--no-install-app"),
  installCli: !args.has("--no-install-cli"),
};

const APP_NAME = FLAGS.production ? "ZCode" : "ZCode Preview";
const previewIdentity = !FLAGS.production;

function expandHome(p) {
  return p.startsWith("~") ? join(process.env.HOME ?? "", p.slice(1)) : p;
}

function run(cmd, cwd = repoRoot, env = process.env) {
  console.log(`\n$ cd ${cwd} && ${cmd}`);
  execFileSync(cmd, { cwd, env, stdio: "inherit", shell: true });
}

function step(name) {
  console.log(`\n=== ${name} ===`);
}

function fail(message) {
  console.error(`\n[lanic-upgrade] 失败：${message}`);
  process.exit(1);
}

// ── 0. 前置检查 ────────────────────────────────────────────────────────────

step("前置检查");
if (!existsSync(contentPluginsRoot)) {
  fail(`内容插件快照缺失：${contentPluginsRoot}（官方退役后这是唯一来源，不能丢）`);
}
const snapshotDir = readdirSync(contentPluginsRoot)
  .filter((d) => d.startsWith("official-"))
  .sort()
  .at(-1);
if (!snapshotDir) fail(`${contentPluginsRoot} 下没有 official-* 快照`);
const snapshotRoot = join(contentPluginsRoot, snapshotDir);
console.log(`内容插件快照：${snapshotRoot}`);

const branch = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], { cwd: repoRoot })
  .toString()
  .trim();
if (branch !== "local/lanic") fail(`当前分支是 ${branch}，必须在 local/lanic 上操作`);
const dirty = execFileSync("git", ["status", "--porcelain"], { cwd: repoRoot }).toString().trim();
if (dirty) fail(`工作树不干净：\n${dirty}\n（先提交或暂存；流水线不做隐式丢弃）`);

// ── 1. upstream 同步 ──────────────────────────────────────────────────────

if (FLAGS.upstream) {
  step("upstream 同步");
  let fetched = false;
  for (let attempt = 1; attempt <= 3 && !fetched; attempt += 1) {
    try {
      run("git fetch upstream main");
      fetched = true;
    } catch (error) {
      console.warn(`fetch 第 ${attempt} 次失败（代理断流常见）：${error.message}`);
    }
  }
  if (!fetched) fail("git fetch upstream 三次失败；检查代理或加 --no-upstream 跳过");
  run("git merge --no-edit upstream/main");
}

// ── 2. 版本递进 ────────────────────────────────────────────────────────────

if (FLAGS.bump) {
  step("版本递进（数字假版本，保 semver）");
  const pkgPath = join(repoRoot, "package.json");
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(pkg.version ?? "");
  if (!match) fail(`当前版本 ${pkg.version} 不是纯 semver，递进规则不适用`);
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]) < 100 ? 100 : Number(match[3]) + 1;
  pkg.version = `${major}.${minor}.${patch}`;
  writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
  run(`git add package.json && git commit -m "chore(fork): bump version to ${pkg.version}"`);
  console.log(`版本 → ${pkg.version}`);
}

// ── 3. 构建 ────────────────────────────────────────────────────────────────

step("构建桌面（production 后端；remote-assets 是远端 agent 资产，桌面包不需要）");
// ZCODE_PRODUCT_FLAVOR 在构建期烤进 out/（tsup/vite define），必须与打包身份一致：
// prod-flavor 代码装进 Preview 壳会在启动期身份错配静默退出（装后冒烟抓过实案）。
run(
  `ZCODE_ENV=production ${previewIdentity ? "ZCODE_PREVIEW_IDENTITY=1 " : ""}ZCODE_SKIP_REMOTE_ASSETS=1 pnpm --filter @zcode/desktop build`,
  repoRoot,
);

step("构建 CLI（bootstrap 先出 dist，CLI bundle 嵌的是它）");
run("pnpm run build", join(cliWorkspace, "packages", "bootstrap"));
run("pnpm run build", join(cliWorkspace, "packages", "cli"));

// ── 4. 注入内容插件 ────────────────────────────────────────────────────────

step("注入内容插件（prepare 会整删 glm，注入必须在其后）");
const glmPackages = join(
  desktopDir,
  "bundled-agents",
  "darwin-arm64",
  "glm",
  "packages",
);
const builtIn = new Set(["browser-use-plugin", "node-repl-host", "bundled-skills"]);
if (existsSync(glmPackages)) {
  for (const entry of readdirSync(glmPackages)) {
    if (!builtIn.has(entry)) rmSync(join(glmPackages, entry), { recursive: true, force: true });
  }
}
let injected = 0;
for (const entry of readdirSync(snapshotRoot)) {
  run(`ditto '${join(snapshotRoot, entry)}' '${join(glmPackages, entry)}'`);
  injected += 1;
}
console.log(`注入 ${injected} 个内容插件（来自 ${snapshotDir}）`);

// ── 5. 打包 + 收割 .app ────────────────────────────────────────────────────

step("electron-builder 打包（skip-prepare/skip-build：产物与注入都已就位）");
const bundleEnv = {
  ...process.env,
  ZCODE_ENV: "production",
  ...(previewIdentity ? { ZCODE_PREVIEW_IDENTITY: "1" } : {}),
};
const builder = spawn(
  process.execPath,
  ["scripts/bundle.mjs", "--skip-prepare", "--skip-build"],
  { cwd: desktopDir, env: bundleEnv, stdio: ["ignore", "pipe", "pipe"] },
);
let zipPhaseStarted = false;
builder.stdout.on("data", (d) => {
  const text = d.toString();
  if (text.includes("building block map")) zipPhaseStarted = true;
  process.stdout.write(`[bundle] ${d}`);
});
builder.stderr.on("data", (d) => process.stderr.write(`[bundle!] ${d}`));

const appPath = join(desktopDir, "dist", "mac-arm64", `${APP_NAME}.app`);
const startedAt = Date.now();
while (Date.now() - startedAt < 8 * 60_000) {
  if (existsSync(join(appPath, "Contents", "Resources", "app.asar"))) break;
  await new Promise((r) => setTimeout(r, 5_000));
}
if (!existsSync(join(appPath, "Contents", "Resources", "app.asar"))) {
  fail("8 分钟内 .app 未产出；查看上方 [bundle] 日志");
}
// asar 出现 ≠ .app 定稿：Electron 的 locale .pak 等 Framework 资源在 asar 之后
// 继续落盘，提前收割会打出「locale resources are not loaded」的残包（深签也过）。
// zip/blockmap 阶段开始才是 .app 内容定稿信号；等不到则超时兜底。
const zipDeadline = Date.now() + 10 * 60_000;
while (!zipPhaseStarted && Date.now() < zipDeadline) {
  await new Promise((r) => setTimeout(r, 3_000));
}
if (!zipPhaseStarted) {
  console.warn("[lanic-upgrade] 未等到 blockmap 阶段，按超时继续（产物可能未定稿）");
  await new Promise((r) => setTimeout(r, 30_000));
} else {
  await new Promise((r) => setTimeout(r, 5_000));
}
for (const signal of ["SIGTERM", "SIGKILL"]) {
  try {
    builder.kill(signal);
  } catch {}
  await new Promise((r) => setTimeout(r, 1_000));
}
// ── 5.5 更新 feed 产出 ─────────────────────────────────────────────────────

// 自托管更新源三件套：manifest YAML（legacy path+sha512 形状，ManifestUpdateProvider
// 原生兼容）+ zip + blockmap（差分更新用）。上传到 ZCODE_FORK_UPDATE_FEED_URL 指向的
// 目录即构成完整 feed；不设该构建变量时产物照常生成，只是应用端更新链保持关闭。
// 注意：provider 把文件 URL 解析到域名根（new URL(path, new URL("/", manifestUrl))），
// feed 挂在子路径下时 yaml 的 path 必须带同样的子目录前缀，否则下载 404。
{
  const { createHash } = await import("node:crypto");
  const feedDir = join(desktopDir, "dist", "feed");
  rmSync(feedDir, { recursive: true, force: true });
  const { mkdirSync, copyFileSync, writeFileSync: wf } = await import("node:fs");
  mkdirSync(feedDir, { recursive: true });
  const pkgNow = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
  const zipName = `${APP_NAME}-${pkgNow.version}-mac-arm64.zip`;
  const zipPath = join(desktopDir, "dist", zipName);
  if (!existsSync(zipPath)) fail(`feed 产物缺失：${zipPath}`);
  const feedUrlRaw = process.env.ZCODE_FORK_UPDATE_FEED_URL?.trim() ?? "";
  let feedPathPrefix = "";
  if (feedUrlRaw) {
    let feedUrl;
    try {
      feedUrl = new URL(feedUrlRaw);
    } catch {
      fail(`ZCODE_FORK_UPDATE_FEED_URL 不是合法 URL：${feedUrlRaw}`);
    }
    feedPathPrefix = feedUrl.pathname
      .slice(0, feedUrl.pathname.lastIndexOf("/") + 1)
      .replace(/^\/+/, "");
  }
  const sha512 = createHash("sha512").update(readFileSync(zipPath)).digest("base64");
  copyFileSync(zipPath, join(feedDir, zipName));
  if (existsSync(`${zipPath}.blockmap`)) copyFileSync(`${zipPath}.blockmap`, join(feedDir, `${zipName}.blockmap`));
  wf(
    join(feedDir, "latest-mac.yml"),
    `version: ${pkgNow.version}\npath: ${feedPathPrefix}${zipName}\nsha512: ${sha512}\n`,
  );
  console.log(`feed 产出：${feedDir}（latest-mac.yml + ${zipName} + blockmap）`);
  if (feedUrlRaw) {
    console.log(
      `feed path 前缀：${feedPathPrefix || "（域名根）"}；把三件套上传到 ${feedUrlRaw} 所在目录即完成发布`,
    );
  }
}

// kill 后 builder 的子进程可能仍在向 .app 内写入（asar repack/unpacked 落盘），
// 立即签名会盖住半成品然后 verify 报 sealed resource invalid。等进程退净再签。
for (let i = 0; i < 15; i += 1) {
  try {
    execFileSync("pgrep", ["-f", "electron-builder"], { stdio: "ignore" });
    await new Promise((r) => setTimeout(r, 1_000));
  } catch {
    break; // pgrep 无匹配退出码 1 = 已退净
  }
}
await new Promise((r) => setTimeout(r, 3_000));
run(`codesign --force --deep --sign - '${appPath}'`);
try {
  run(`codesign --verify --deep '${appPath}'`);
} catch {
  // 兜底一轮：清理残留进程后重签再验。
  run("pkill -9 -f electron-builder || true");
  await new Promise((r) => setTimeout(r, 3_000));
  run(`codesign --force --deep --sign - '${appPath}'`);
  run(`codesign --verify --deep '${appPath}'`);
}

// ── 6. 安装 ────────────────────────────────────────────────────────────────

if (FLAGS.installCli) {
  step("安装 CLI（mv 原子换名，在役进程不受打断）");
  const cliDist = join(cliWorkspace, "packages", "cli", "dist");
  run(`cp '${join(cliDist, "zcode.cjs")}' /tmp/lanic-zcode.cjs && mv -f /tmp/lanic-zcode.cjs '${join(liveCliDir, "zcode.cjs")}'`);
  run(`cp '${join(cliDist, "provider", "zcode-builtin.json")}' /tmp/lanic-builtin.json && mv -f /tmp/lanic-builtin.json '${join(liveCliDir, "provider", "zcode-builtin.json")}'`);
  run(`node '${join(liveCliDir, "zcode.cjs")}' --version`);
}

if (FLAGS.installApp) {
  step(`安装 ${APP_NAME}.app（按 PID 换 app）`);
  // 主进程 ps 里只显示短名、pgrep -f 匹配不到完整路径：主进程用 -x 精确名，
  // helper 用 bundle 路径片段；两者缺席都是正常态（首次安装）。
  const pids = new Set();
  for (const argv of [["-x", APP_NAME], ["-f", `${APP_NAME}.app/Contents`]]) {
    try {
      execFileSync("pgrep", argv, { encoding: "utf8" })
        .trim()
        .split("\n")
        .filter(Boolean)
        .forEach((pid) => pids.add(pid));
    } catch {}
  }
  for (const pid of pids) {
    try {
      process.kill(Number(pid), "SIGTERM");
    } catch {}
  }
  if (pids.size > 0) await new Promise((r) => setTimeout(r, 3_000));
  rmSync(join("/Applications", `${APP_NAME}.app`), { recursive: true, force: true });
  run(`ditto '${appPath}' '/Applications/${APP_NAME}.app'`);
  run(`codesign --verify --deep '/Applications/${APP_NAME}.app'`);
  run(`open '/Applications/${APP_NAME}.app'`);
  // 启动冒烟：codesign 深验过不了「收割竞态残包」这一关（签名能盖住半成品，
  // 应用却在数秒内 exit 0 静默退）。装完必须实证主进程 15s 存活。
  await new Promise((r) => setTimeout(r, 12_000));
  try {
    execFileSync("pgrep", ["-x", APP_NAME], { stdio: "ignore" });
    console.log(`[lanic-upgrade] 启动冒烟通过：${APP_NAME} 主进程存活`);
  } catch {
    fail(
      `启动冒烟失败：${APP_NAME} 装后 12s 内退出。产物疑似收割竞态残包，` +
        `回退手段=重跑本脚本（构建瞬态损坏，实测重现率低）；dist 产物在 ${appPath}`,
    );
  }
}

// ── 7. push + T3 ───────────────────────────────────────────────────────────

if (FLAGS.push) {
  step("推送 fork");
  run("git push origin local/lanic");
} else {
  console.log("（--no-push：跳过推送）");
}

if (FLAGS.kickstartT3) {
  step("重建并 kickstart T3 server（显式部署动作）");
  const t3Server = expandHome("~/projects/t3code-expanded/apps/server");
  run("pnpm run build:bundle", t3Server);
  run(`launchctl kickstart -k gui/$(id -u)/com.lanic.t3.server`);
}

console.log(`\n[lanic-upgrade] 完成：${APP_NAME} ${JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")).version} 已装。`);
