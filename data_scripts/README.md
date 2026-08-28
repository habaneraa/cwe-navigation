# data_scripts

CWE 导航数据生成管道(nodejs/npm workspace)。

- **nodejs/**(TypeScript):数据管道,已接入主仓库 build,生成前端使用的
  `public/` 数据
- **fixture/**:小型合成 CWE 目录 + golden 基线(`expected/`,回归测试用;
  有意变更输出后用 `gen:fixture` 重新生成)
- **cache/**:输入缓存(不入库)

> 历史注:本管道自 python 实现(`cwe_catalog.py`)逐字节迁移而来,
> 迁移期间以 python 产出为对照基线完成了全量验证(CWE 4.20,
> `cwe_metadata.json` 逐字节一致;`graph_data.json` 仅 "Popular
> Weaknesses" 节点顺序差异——源于 python `set()` 迭代的非确定性,
> canonical 化后逐字节一致)。python 实现及对照工具链已随迁移完成退役;
> 输出序列化也随之换成了原生 `JSON.stringify`。

## 数据来源

输入文件:`cache/cwec_latest.xml`(从
https://cwe.mitre.org/data/xml/cwec_latest.xml.zip 下载解压,`cache/`
不入库)。缓存缺失时自动下载,`--download` 强制刷新。
当前基线:CWE 4.20 (2026-04-30)。

## 使用(主仓库根目录)

`data_scripts/nodejs` 是根 `package.json` 的 workspace,依赖统一收敛到根
`package-lock.json`,根目录一次 `npm install` 即可。

```bash
npm install                # 根目录一次安装(app + data_scripts)
npm run data:generate      # 生成数据 -> public/(自动下载缺失的 XML 缓存)
npm run data:test          # vitest:fixture golden 基线
npm run data:typecheck     # tsc --noEmit
npm run build              # data:generate + vite build(public/ 数据随构建刷新)
```

`generate` 的输出规则:

- 默认写 `<repo>/public/`,前端直接消费
- `--out <dir>`:写到指定目录并附加 `node_manifest.json`
  (CWE 版本、日期、源 XML SHA256 等溯源信息),用于调试
- `--download`:强制重新下载 CWE XML

进入子目录后,原有命令仍然可用(依赖由根 `node_modules` 提升):

```bash
cd data_scripts/nodejs
npm run generate           # 同 data:generate
npm test                   # vitest
npm run typecheck
npm run gen:fixture        # 有意变更输出后,重新生成 fixture/expected/ 基线
```

结构:

| 文件 | 职责 |
|---|---|
| `src/xmltodict.ts` | xmltodict 兼容解析(基于 fast-xml-parser,重建其输出形态) |
| `src/digraph.ts` | networkx.DiGraph 子集的移植(插入序迭代语义) |
| `src/cwe_catalog.ts` | CWE 目录数据模型 + 图表数据组装 |
| `src/generate.ts` | 管道入口:下载/缓存 XML,输出 public/ 数据 |
| `test/fixture.test.ts` | fixture golden 基线回归 |
| `../fixture/update-baseline.ts` | golden 基线再生脚本(`gen:fixture`) |

注意:vitest 3 依赖 vite `^5||^6||^7`,主仓库是 vite 8,npm 会自动在
`node_modules/vitest` 下嵌套一份 vite 7,互不影响。

## 实现注意事项

1. **输出是紧凑 JSON**(`JSON.stringify`,键保持插入序),重新生成的
   diff 只含真实数据变化。`fixture.test.ts` 的 golden 基线会逐字节
   比对,防止重构悄悄改变导出数据;有意变更输出时跑 `gen:fixture`
   并 review 基线 diff。
2. `show_cwe_basic_info` 控制台输出里的 "Commmon" 拼写错误继承自原
   python 管道,按原样保留。
3. fast-xml-parser v5 不解码数值字符实体(`&#233;`),`src/xmltodict.ts`
   自行做了单遍实体解码(命名 + 数值),与 expat/xmltodict 行为一致。
4. 已知对齐自原实现的边界行为:graph 中存在但 tree 中不存在的节点会让
   `findPathOnTree` 抛错(parentMap 缺 key;真实数据恰好不触发)。
