// 渐进增强入口：无 JavaScript 时页面与表单仍可正常工作。
// 只挂载 data-ln-module 明确声明的模块，不读取任何秘密，不拼接远端资源。
//
// 局部替换页面内容（例如列表搜索/统计刷新）后，增强模块可通过
// window.__lnMountModules(root) 重新挂载新 DOM 中的模块；本入口只做一次声明式
// 挂载，不假设页面永远不变化。
const modules = {
  "confirm": () => import("./modules/confirm.mjs"),
  "async-form": () => import("./modules/async-form.mjs"),
  "webauthn": () => import("./modules/webauthn.mjs"),
  "qr-poll": () => import("./modules/qr.mjs"),
  "qr-claim": () => import("./modules/qr.mjs"),
  "qr-countdown": () => import("./modules/qr.mjs"),
  "secret-copy": () => import("./modules/secret-copy.mjs"),
  "stats-refresh": () => import("./modules/stats-refresh.mjs"),
  "list-search": () => import("./modules/list-search.mjs"),
};

// mountAll 挂载 root 内所有已声明模块；单个模块加载/挂载失败不影响其他模块与
// 服务端渲染的普通表单、链接。
function mountAll(root) {
  for (const element of root.querySelectorAll("[data-ln-module]")) {
    const name = element.getAttribute("data-ln-module");
    const loader = modules[name];
    if (!loader) continue;
    loader().then((module) => {
      try {
        module.mount(element, { basePath: element.getAttribute("data-ln-base-path") || "" });
      } catch {
        // 单个模块挂载失败不阻断其余增强。
      }
    }).catch(() => {
      // 增强失败不影响服务端渲染的普通表单与导航。
    });
  }
}

mountAll(document);

if (typeof window !== "undefined") {
  // 局部内容替换后由增强模块调用，重新挂载新 DOM 中的模块。
  window.__lnMountModules = mountAll;
}
