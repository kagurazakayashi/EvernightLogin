# 第三方组件与字体许可证清单（步骤 78）

本文件覆盖报告 PDF 渲染新增的直接依赖、传递依赖与嵌入字体。发行包需随附本文件与
`docs/licenses/NotoSansSC-OFL.txt`（字体许可证全文）。

## 1. 软件依赖

### 1.1 github.com/signintech/gopdf v0.38.4 — MIT

- 用途：纯 Go PDF 生成（步骤 78 报告 PDF 渲染）。
- 来源：<https://github.com/signintech/gopdf>，tag `v0.38.4`（commit
  `d29f9ab125c2c45fa2afc280793578d4a8732e7a`）。
- 版本锁定：`go.mod` 固定 `v0.38.4`，`go.sum` 校验；升级需重新预审并做渲染 smoke test。

```
The MIT License (MIT)

Copyright (c) 2015 signintech

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

### 1.2 github.com/phpdave11/gofpdi v1.0.14-0.20211212211723-1f10f9844311 — MIT

- 用途：gopdf 的传递依赖（gopdf 内部导入既有 PDF 的能力）。本项目的报告生成不调用
  `StartWithImporter`/gofpdi，不使用该导入能力。
- 来源：<https://github.com/phpdave11/gofpdi>。

```
The MIT License (MIT)

Copyright (c) 2019-2020 David Barnes
Copyright (c) 2017 Setasign - Jan Slabon, https://www.setasign.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

### 1.3 github.com/pkg/errors v0.8.1 — BSD-2-Clause

- 用途：gofpdi 的传递依赖（仅错误包装）。
- 来源：<https://github.com/pkg/errors>。

```
Copyright (c) 2015, Dave Cheney <dave@cheney.net>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## 2. 嵌入字体：Noto Sans SC Regular（SIL OFL 1.1）

- 文件：`NotoSansSC-Regular.ttf`（静态 Regular TrueType/glyf，10,540,644 字节，
  SHA-256 `450625c8d46ab3df97b7904ded955ec2746d17ec76740cb1e91d1ba63a0f89af`）。
- 来源：Google Fonts 官方 CDN（`fonts.gstatic.com`，Noto Sans SC v41）静态文件；
  与 `google/fonts` 仓库 `ofl/notosanssc` 同一字体家族。
- 许可证：SIL Open Font License 1.1，全文见 `docs/licenses/NotoSansSC-OFL.txt`
  （4,388 字节，SHA-256
  `1c05c68c34f9708415aada51f17e1b0092d2cea709bf4a94cd38114f9e73d7d9`）。
- 版权：`Copyright 2014-2021 Adobe (http://www.adobe.com/), with Reserved Font Name
  'Source'`。
- 分发要求：再分发时必须随附上述版权声明与 OFL 1.1 全文；不得单独售卖字体；对字体
  做修改/子集化时不得使用保留字体名 `Source`。本项目的 PDF 只做嵌入所需的子集化，
  子集字体名由 gopdf 生成（`NotoSansSC`），不含保留名。
- 字体文件不提交到 Git 仓库（10.5 MB 二进制）；宿主部署时通过受信本地路径
  （`reports.Options.FontPath`）提供，或用 `scripts/fetch-report-font.ps1` 获取并校验
  SHA-256。使用该字体生成的报告文档不受 OFL 约束。
- 已审查但被否决的方案：`notofonts/noto-cjk` 的 OTF/OTC 为 CFF 轮廓，gopdf 解析器
  不支持；`google/fonts` 的 `NotoSansSC[wght].ttf` 是可变字体且默认实例为 Thin，
  gopdf 忽略 `fvar`/`gvar`，会嵌入 Thin 字重。
