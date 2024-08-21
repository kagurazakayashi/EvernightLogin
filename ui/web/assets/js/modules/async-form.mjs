// 异步/提交增强：仅做防重复提交与状态提示；服务端仍负责幂等、CSRF 与最终校验。
export function mount(root, context) {
  const form = root.tagName === "FORM" ? root : root.querySelector("form");
  if (!form) return () => {};
  let pending = false;
  const onSubmit = () => {
    if (pending) return;
    pending = true;
    const button = form.querySelector("button[type=submit]");
    if (button) {
      button.setAttribute("aria-busy", "true");
      button.setAttribute("aria-disabled", "true");
    }
  };
  form.addEventListener("submit", onSubmit);
  return () => form.removeEventListener("submit", onSubmit);
}
