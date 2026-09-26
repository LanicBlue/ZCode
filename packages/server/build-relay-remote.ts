import { readFileSync } from "node:fs";
import { build, type Plugin } from "esbuild";

/**
 * entry-relay 的单文件自包含 bundle（Caddy 前置部署用）。
 *
 * 与 tsup 的 dist/ 不同：tsup 默认把 package.json 依赖外置（hono/ws 等
 * 运行时 require node_modules），部署到无 node_modules 的目标机（ECS）
 * 会 ERR_MODULE_NOT_FOUND。这里照 build-remote.ts 的配方全量内联，
 * CJS 输出原生支持 __dirname；.node 原生 addon 保持 external（中继形态
 * 不装配本地服务，正常不触发 pty 加载）。
 */
const nativeAddonPlugin: Plugin = {
  name: "native-addon",
  setup(build) {
    build.onResolve({ filter: /\.node$/ }, (args) => ({
      path: args.path,
      external: true,
    }));
  },
};

const { version } = JSON.parse(readFileSync("../../package.json", "utf8"));

await build({
  entryPoints: ["src/entry-relay.ts"],
  bundle: true,
  outfile: "dist/remote/entry-relay.cjs",
  platform: "node",
  format: "cjs",
  target: "node22",
  plugins: [nativeAddonPlugin],
  banner: {
    js: 'var __import_meta_url = require("url").pathToFileURL(__filename).href; var __import_meta_dirname = __dirname;',
  },
  define: {
    "import.meta.url": "__import_meta_url",
    "import.meta.dirname": "__import_meta_dirname",
    __ZCODE_VERSION__: JSON.stringify(version),
  },
});
console.log("[build-relay-remote] dist/remote/entry-relay.cjs 完成");
