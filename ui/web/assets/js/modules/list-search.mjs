// 管理页列表搜索渐进增强（步骤 261）：用户列表与应用成员列表共用的防抖搜索。
//
// 竞态不变量（与 statistics 页 stats-refresh 相同的服务端渲染 + 局部替换模式）：
//   - 全局只允许一个在途请求；新搜索/筛选/翻页开始时中止旧请求并递增序号；
//   - 只有序号仍是最新且页面未卸载时，才用响应中的 main#main 局部替换；
//   - 迟到/被忽略的响应只更新一次礼貌状态文本，不覆盖新结果、不弹错误；
//   - 输入框 300ms 防抖：连续输入只发最后一次请求；提交/翻页立即执行；
//   - 会话、CSRF、授权与数据范围仍由服务端每次请求重新判定，前端不缓存权限；
//   - 无 JavaScript 时表单与链接仍是普通 GET 导航，页面完全可用。
// 局部替换后通过 app.mjs 暴露的 window.__lnMountModules 重新挂载新 DOM 中的
// data-ln-module（async-form 等），不在本模块内重复实现其他模块。

const DEBOUNCE_MS = 300;
const SEARCH_FIELD = 'input[type="search"][name="search"]';

let inFlightController = null;
let latestSequence = 0;
let debounceTimer = null;
let disposed = false;

function mainElement() {
  return document.querySelector("main#main");
}

function statusElements(root) {
  return root.querySelectorAll("[data-ln-list-status]");
}

function stringsOf(element) {
  const doc = element.ownerDocument || document;
  const source = doc.querySelector("[data-ln-module='list-search']") || element;
  return {
    loading: source.getAttribute("data-ln-loading") || "",
    updated: source.getAttribute("data-ln-updated") || "",
    cancelled: source.getAttribute("data-ln-cancelled") || "",
    ignored: source.getAttribute("data-ln-ignored") || "",
    failed: source.getAttribute("data-ln-failed") || "",
  };
}

function setStatus(root, text) {
  if (!text) {
    return;
  }
  for (const element of statusElements(root)) {
    element.textContent = text;
  }
}

function setBusy(busy) {
  const main = mainElement();
  if (!main) {
    return;
  }
  if (busy) {
    main.setAttribute("aria-busy", "true");
  } else {
    main.removeAttribute("aria-busy");
  }
}

// buildSearchURL 从表单当前值构造同页 GET URL：搜索/筛选改变时重置 offset，
// 翻页链接则直接使用链接自身的 URL。
function buildSearchURL(form) {
  const url = new URL(form.action, window.location.href);
  url.search = "";
  const values = new FormData(form);
  for (const [key, value] of values.entries()) {
    if (typeof value !== "string" || value === "") {
      continue;
    }
    url.searchParams.append(key, value);
  }
  url.searchParams.delete("offset");
  return url.toString();
}

async function load(url, pushHistory, strings) {
  if (inFlightController) {
    inFlightController.abort();
  }
  const controller = new AbortController();
  inFlightController = controller;
  const sequence = ++latestSequence;
  setBusy(true);
  const main = mainElement();
  if (main) {
    setStatus(main, strings.loading);
  }
  let response;
  try {
    response = await fetch(url, {
      credentials: "same-origin",
      cache: "no-store",
      redirect: "follow",
      headers: { Accept: "text/html" },
      signal: controller.signal,
    });
  } catch (error) {
    if (sequence !== latestSequence || disposed) {
      if (main) setStatus(main, strings.ignored);
      return;
    }
    if (main) {
      setStatus(main, error && error.name === "AbortError" ? strings.cancelled : strings.failed);
    }
    setBusy(false);
    return;
  }
  if (sequence !== latestSequence || disposed) {
    return;
  }
  const contentType = response.headers.get("Content-Type") || "";
  if (!contentType.includes("text/html")) {
    if (main) setStatus(main, strings.failed);
    setBusy(false);
    return;
  }
  let text;
  try {
    text = await response.text();
  } catch (error) {
    if (sequence !== latestSequence || disposed) {
      return;
    }
    if (main) setStatus(main, strings.failed);
    setBusy(false);
    return;
  }
  if (sequence !== latestSequence || disposed) {
    return;
  }
  const parsed = new DOMParser().parseFromString(text, "text/html");
  const nextMain = parsed.querySelector("main#main");
  const currentMain = mainElement();
  if (!nextMain || !currentMain) {
    setStatus(currentMain || document, strings.failed);
    setBusy(false);
    return;
  }
  // 只在序号最新时整体替换同一上下文；旧结果不会与新搜索条件拼接。
  currentMain.innerHTML = nextMain.innerHTML;
  currentMain.setAttribute("tabindex", "-1");
  if (pushHistory) {
    history.pushState(null, "", url);
  } else {
    history.replaceState(null, "", url);
  }
  if (currentMain.focus) {
    currentMain.focus();
  }
  setBusy(false);
  // 重新挂载新 DOM 中的渐进增强模块（含本模块自身），再恢复状态文本。
  if (typeof window !== "undefined" && typeof window.__lnMountModules === "function") {
    window.__lnMountModules(currentMain);
  }
  setStatus(currentMain, strings.updated);
}

// applySearch 触发一次搜索请求；清空输入等价于空搜索（保持原列表）。
function applySearch(form) {
  if (!form) {
    return;
  }
  const strings = stringsOf(form);
  load(buildSearchURL(form), true, strings);
}

// mount 绑定指定容器（初始 main，或局部替换后的新 main）。
export function mount(element) {
  disposed = false;
  const root = mainElement() || document;
  const form = root.querySelector("form.ln-list-search");
  if (!form) {
    return () => {};
  }

  form.addEventListener("input", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement) || !target.matches(SEARCH_FIELD)) {
      return;
    }
    if (debounceTimer !== null) {
      clearTimeout(debounceTimer);
    }
    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      applySearch(form);
    }, DEBOUNCE_MS);
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (debounceTimer !== null) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }
    applySearch(form);
  });

  // 同页翻页/排序链接走异步更新（中止旧请求），跨页面链接保持普通导航。
  root.querySelectorAll("a[href]").forEach((anchor) => {
    const target = new URL(anchor.href, window.location.href);
    if (target.origin !== window.location.origin || target.pathname !== window.location.pathname) {
      return;
    }
    if (target.search === window.location.search) {
      return;
    }
    anchor.addEventListener("click", (event) => {
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) {
        return;
      }
      event.preventDefault();
      load(target.toString(), true, stringsOf(form));
    });
  });

  return () => {
    disposed = true;
    if (debounceTimer !== null) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }
    if (inFlightController) {
      inFlightController.abort();
      inFlightController = null;
    }
  };
}
