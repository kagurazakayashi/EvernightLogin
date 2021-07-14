// 渐进增强入口：无 JavaScript 时页面与表单仍可正常工作。
// 只挂载 data-ln-module 明确声明的模块，不读取任何秘密，不拼接远端资源。
const modules = {
  "confirm": () => import("./modules/confirm.mjs"),
  "async-form": () => import("./modules/async-form.mjs"),
  "webauthn": () => import("./modules/webauthn.mjs"),
};

for (const element of document.querySelectorAll("[data-ln-module]")) {
  const name = element.getAttribute("data-ln-module");
  const loader = modules[name];
  if (!loader) continue;
  loader().then((module) => {
    module.mount(element, { basePath: element.getAttribute("data-ln-base-path") || "" });
  }).catch(() => {
    // 增强失败不影响服务端渲染的普通表单与导航。
  });
}
