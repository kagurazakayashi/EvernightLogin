// 步骤 76 统计看板异步增强：筛选、排序、分页与手动刷新在同一页面内局部更新。
//
// 竞态不变量：
//   - 全局只允许一个在途请求；新请求开始时中止旧请求，并递增请求序号；
//   - 响应只有在序号仍是最新、页面未卸载时才替换内容；
//   - 迟到/被忽略的响应只更新一次礼貌状态文本，不覆盖新筛选结果、不弹错误；
//   - 会话、CSRF、授权全部仍由服务端每次请求重新判定，前端不缓存权限。
// 无 JavaScript 时表单与链接仍是普通 GET 导航，页面完全可用。

let inFlightController = null;
let latestSequence = 0;
let disposed = false;

function mainElement() {
  return document.querySelector("main#main");
}

function statusElement() {
  return document.querySelector("[data-ln-stats-status]");
}

function setStatus(text) {
  const element = statusElement();
  if (!element || !text) {
    return;
  }
  element.textContent = text;
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

function stringsOf(element) {
  return {
    loading: element.getAttribute("data-ln-loading") || "",
    updated: element.getAttribute("data-ln-updated") || "",
    cancelled: element.getAttribute("data-ln-cancelled") || "",
    ignored: element.getAttribute("data-ln-ignored") || "",
    failed: element.getAttribute("data-ln-failed") || "",
  };
}

async function load(url, pushHistory, strings) {
  if (inFlightController) {
    inFlightController.abort();
  }
  const controller = new AbortController();
  inFlightController = controller;
  const sequence = ++latestSequence;
  setBusy(true);
  setStatus(strings.loading);
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
    if (sequence !== latestSequence) {
      setStatus(strings.ignored);
      return;
    }
    // 主动取消与被新请求取代都只提示一次，不当作失败。
    setStatus(error && error.name === "AbortError" ? strings.cancelled : strings.failed);
    setBusy(false);
    return;
  }
  if (sequence !== latestSequence || disposed) {
    setStatus(strings.ignored);
    return;
  }
  const contentType = response.headers.get("Content-Type") || "";
  if (!contentType.includes("text/html")) {
    setStatus(strings.failed);
    setBusy(false);
    return;
  }
  let text;
  try {
    text = await response.text();
  } catch (error) {
    if (sequence !== latestSequence) {
      setStatus(strings.ignored);
      return;
    }
    setStatus(strings.failed);
    setBusy(false);
    return;
  }
  if (sequence !== latestSequence || disposed) {
    setStatus(strings.ignored);
    return;
  }
  const parsed = new DOMParser().parseFromString(text, "text/html");
  const nextMain = parsed.querySelector("main#main");
  const currentMain = mainElement();
  if (!nextMain || !currentMain) {
    setStatus(strings.failed);
    setBusy(false);
    return;
  }
  // 只在序号最新时整体替换同一上下文；旧图/旧表不会与新筛选拼接。
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
  const nextToolbar = currentMain.querySelector('[data-ln-module="stats-refresh"]');
  if (nextToolbar) {
    mount(nextToolbar);
  }
  setStatus(strings.updated);
}

export function mount(element) {
  disposed = false;
  const strings = stringsOf(element);
  const main = mainElement() || document;

  element.addEventListener("click", (event) => {
    const refresh = event.target.closest("[data-ln-stats-refresh]");
    if (!refresh) {
      return;
    }
    event.preventDefault();
    load(refresh.href, false, strings);
  });
  // 同页排序与分页链接也走异步更新；跨页面链接仍使用普通导航。
  main.querySelectorAll("a[href]").forEach((anchor) => {
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
      load(target.toString(), true, strings);
    });
  });
  main.querySelectorAll("form.ln-stats-filter").forEach((form) => {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const url = new URL(form.action, window.location.href);
      url.search = "";
      const values = new FormData(form);
      for (const [key, value] of values.entries()) {
        if (typeof value === "string" && value !== "") {
          url.searchParams.append(key, value);
        }
      }
      load(url.toString(), true, strings);
    });
  });
  return () => {
    disposed = true;
    if (inFlightController) {
      inFlightController.abort();
      inFlightController = null;
    }
  };
}
