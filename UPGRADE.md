# BlackObfuscator 升级与评估记录

> 记录时间：2026-11-27
> 分支：`jar2dex-2.2`

---

## 一、结论先行

这次工作的成果和局限，先讲清楚：

### 做成了什么

| 项 | 状态 |
|---|---|
| 工具链现代化（Gradle 9 / JDK 17 / dex2jar 2.4 / ASM 9） | ✅ 完成 |
| 修掉 8 个 bug（其中 2 个会导致静默产错包） | ✅ 完成 |
| 混淆模块化，可独立开关、自由组合 | ✅ 完成 |
| 真实 App 全量混淆（707 类），dx/d8 均可回转 | ✅ 完成 |
| 真机安装运行验证 | ✅ 通过 |

### 没做成什么

**控制流混淆的强度没有实质提升。**

自建 5 种反平坦化攻击的实测结果（`MainActivity`，87 个块 / 79 条边）：

| 攻击 | 还原率 |
|---|---|
| A1 hash 原像 | 0.0% |
| A2 groupBy 合并 | 78.5% |
| A3 MBA 规范化 | 121.5% |
| A4 谓词剪枝 | 163.3% |
| **A5 出口签名连边** | **100.0%** |

**A5 是最致命的一条，也是理解整个问题的关键。**

---

## 二、为什么强度上不去（核心问题）

### 泄漏点在「块尾的明文 key」，不在「state 怎么算」

原 `FlowObfuscator` 的状态转移设计：

```java
// 每个块的出口
obfStr = "Iۛ᩷ܳ";                    // ← 明文 key，就躺在字节码里
goto dispatcher;

// dispatcher
state = obfStr.hashCode() ^ obfIndexI;
switch (state) { case <某值>: goto 某块; }
```

攻击者**完全不需要计算 state**：

```python
for block in blocks:
    next_key = block.exit_string      # 明文，直接读
    edges.append((block, key_to_block[next_key]))
```

因为「key 集合」是封闭的 —— 每个 key 既作为某块的出口出现，又作为某块的入口。
所以只要收集方法内所有字符串常量，就能把 `块 → 后继块` 的整张图连出来。

这就是 A5 恒为 100% 的原因。

### 这解释了为什么前几轮全部无效

| 轮次 | 加的东西 | 改动位置 | 对 A5 的影响 |
|---|---|---|---|
| v1 | `availableProcessors() > 0` | state 的计算 | 无 |
| v2 | 三条数论恒等式 | state 的计算 | 无 |
| v3 | 12 种谓词随机化 | state 的计算 | 无 |
| v4 | `state + mask*SPACE`，case 表 4 份副本 | case 表的编码 | 无（`groupBy` 可合并） |
| v5 | MBA 算术改写 | state 的计算 | 无 |

**全都在加固「怎么算 state」，而攻击者走的是「块尾那个字符串」。**

这也是为什么每次改动都能被独立评审指出「本质没变」——因为它确实没变。

---

## 三、对照商业混淆器（真实差距）

对比样本：某商业混淆器产出的 `MainActivity.java`（jadx 反编译，2075 行）。

### 它的状态转移

```java
case 1748858:
    if (۟ۥۣ.ۣ۟۟ۨۡ < 0) {
        i = (ۣ۟ۡۨۦ.ۣۨۦ۠ + ۣ۟ۧۨ.ۦ۠ۢ۟) ^ 1750767;
        break;
    } else {
        i = ۣۢۤۢ.ۣ۟ۡۦۨ("۠ۨ");
        break;
    }
```

- 状态值来自**跨类静态字段运算**（`ۣ۟ۡۨۦ.ۣۨۦ۠` + `ۣ۟ۧۨ.ۦ۠ۢ۟`）
- **没有明文 key 字符串**
- case 值域是 `56297 ~ 1755615` 的小整数

攻击者要确定这条边，必须做**全程序数据流分析**：找到那些字段在哪个类赋值、
赋值顺序如何。

### 它的字符串保护

```java
file2 = new File(str, (String) ۣ۟ۤۡ.n(27202, (Object) null,
        new Object[]{(short[]) ۣ۟ۤۡ.n(97586),
                     35,                                    // 在数组中的偏移
                     Integer.valueOf(۟ۥۣ.ۣ۟۟ۨۡ ^ (-19)),   // 异或密钥（也是字段）
                     498}));                                // 长度
```

`"index.html"` 这个字符串在字节码里**完全不存在**：
- 只剩数组索引 `97586`、偏移 `35`、长度 `498`
- 异或密钥 `۟ۥۣ.ۣ۟۟ۨۡ ^ (-19)` 本身也依赖另一个字段

### 它的模块清单 vs 本项目的

| 商业混淆器模块 | 本项目 | 说明 |
|---|---|---|
| **字符串加密** | ❌ **缺** | 最关键，见下节 |
| **加密资源 ID** | ❌ 缺 | |
| **常量/数字混淆** | ❌ 缺 | 部分被 MBA 覆盖 |
| **反射保护** | ❌ 缺 | |
| **去除调试信息** | ❌ 缺 | |
| **dex 优化** | ❌ 缺 | |
| 控制流扁平化 | ✅ `flow` | |
| 条件反折 | ✅ `if` | |
| 指令替换 | ✅ `sub` / `mba` / `instruction-substitution` | |
| 不透明谓词 | ✅ `opaque-predicate` | |

**本项目 6 个模块里，5 个都在改「代码怎么写」，没有一个在保护「数据是什么」。**

而攻击者真正要的（域名、API 路径、签名比对值）**全是数据**。
把控制流搞得再复杂，`strings classes.dex | grep http` 依然直接命中。

### 一个侧面证据

jadx 反编译这两个版本的难度：

| | 商业版 | 本项目 |
|---|---|---|
| `JADX WARN` 数量 | **59 个** | 0 |
| "Code decompiled incorrectly" | **9 处** | 0 |
| 反编译结果 | 部分方法只剩 dump | 干净可读 |

---

## 四、模块清单与用法

### 当前模块

| 模块 | 层级 | 作用 |
|---|---|---|
| `flow` | chain | 控制流平坦化（while + lookupswitch 状态机） |
| `if` | chain | 条件反折 |
| `sub` | chain | 算术改写（`a+b` → `a-(-b)`） |
| `instruction-substitution` | Pass | 指令替换 |
| `opaque-predicate` | Pass | 数论恒等式谓词（12 种，每块随机） |
| `mba` | Pass | MBA 算术混淆（`a+b` → `(a^b)+2*(a&b)` 等） |

### 两层架构

```
ObfuscatorChain  —— 逐【语句】回调，适合改写局部表达式
ObfuscationPass  —— 对整个【方法】做一次整体重写，方法级顺序明确
```

执行顺序：

```
阶段一（chain）：flow → if → sub
阶段二（Pass）：instruction-substitution → opaque-predicate → mba
```

分两层的原因：方法级变换要求「我先、你后」的明确顺序（不透明谓词要包住
平坦化产生的块出口），而逐语句回调天然表达不了。

### 编译

```bash
./gradlew build -x test
```

### 运行

```bash
CP=$(find . -name "*.jar" -path "*libs*" | tr '\n' ':')
CP="$CP$(find ~/.gradle/caches -name 'guava-33.8.0-jre.jar' \
  -o -name 'asm-9.11.1.jar' -o -name 'asm-tree-9.11.1.jar' \
  -o -name 'asm-util-9.11.1.jar' -o -name 'asm-analysis-9.11.1.jar' \
  -o -name 'asm-commons-9.11.1.jar' -o -name 'antlr4-runtime-4.13.2.jar' \
  -o -name 'antlr-runtime-3.5.3.jar' 2>/dev/null | tr '\n' ':')"

java -cp "$CP" com.googlecode.dex2jar.tools.BlackObfuscatorCmd \
  -d 1 -l 3 -i classes.dex -o out.dex -p com.example -m flow,opaque-predicate,mba x
```

### 参数

| 参数 | 含义 |
|---|---|
| `-d, --depth` | chain 重复次数 |
| `-l, --opaque-layers` | 不透明谓词嵌套层数（1~4，默认 2） |
| `-m, --modules` | 启用的模块，逗号分隔；不给则全开 |
| `-p, --package` | **白名单**（只混淆这个包） |
| `-a, --allow` | allowList 文件路径 |
| `-k, --keep` | 保留中间产物（排错必用） |

> ⚠️ 末尾必须给一个位置参数（如 `x`）：`BlackObfuscatorCmd` 里有
> `if (remainingArgs.length == 0) { usage(); return; }`。

> `-p` 是**白名单**，不是黑名单。`splitDex` 的 `whiteList` 为空会直接返回 0。

### 模块组合示例

```bash
-m flow                        # 只平坦化
-m opaque-predicate            # 只谓词
-m flow,opaque-predicate,mba   # 组合
（不给 -m = 全开）
```

---

## 五、实测数据

### 真机 APK（JMComic 2.1.14，classes.dex 1,211,596 B / 707 类）

全模块 + `-l 3`：

| 项 | 结果 |
|---|---|
| 耗时 | 1.5 秒 |
| 产物 | 1,255,296 B |
| 体积变化 | **1.036×** |
| dex2jar 错误 | 0 |
| ASM verifier 失败 | 0 |
| lookupswitch 乱序 | 0（46 个全部升序） |
| d8 回转 | ✅ 0 error |
| 真机安装运行 | ✅ 通过（漫画正文、翻页、章节、评论、收藏正常） |

### 语义回归

`Sem` 测试类（覆盖槽位复用 / long / double / 嵌套循环 / try-catch-finally /
switch 状态机），6 种模块组合 × 4 种谓词层数，全部 7 项输出逐字一致。

### 反平坦化评估

```bash
java -cp "$ASM_CP:/path/to/vcls" DeobfHarness out.dex MainActivity
```

```
真实块数 87 / CFG 边 79
A1 hash 原像还原      0 边    0.0%
A2 groupBy 合并       62 边   78.5%
A3 MBA 规范化         96 条  121.5%
A4 谓词剪枝          129 条  163.3%
A5 出口签名连边       79 边  100.0%
```

---

## 六、已知边界（重要）

| 项 | 说明 |
|---|---|
| **A5 攻击 100% 可还原** | 块尾明文 key 是根本泄漏点，不解决这条，其余加固都无意义 |
| **try-catch 方法不混淆** | `FlowObfuscator` 遇 `ir.traps.size() > 0` 整方法跳过。`p`/`onCreate`/`q`/`onActivityResult` 均在此列（恰好是最大的几个方法） |
| `<init>` 不混淆 | 避免构造器语义被破坏 |
| 字符串全明文 | `https://18comic.vip/`、`server.html` 等直接 `strings` 可读 |
| 类名/方法名不混淆 | 本工具不做，需在 dex 化之前用 R8/ProGuard |
| MBA 只到线性 | 三条恒等式是 degree-1，可用探针求值向量（Eyrolles-Goubin-Videau, SPRO 2016）多项式时间反解 |
| 与 anti-diff 冲突 | 平坦化后 anti-diff 的 E 变换失去意义 |

### 尝试过但失败的方案

**放开 trap 方法平坦化**：立刻复现
```
Uncaught translation error: SimException: local 0002: invalid
```
原因：trap 的 handler 在 loop head 处的类型合并退化为 `UNINITIALIZED_VALUE`。
已回退。

**固定 case 基址 `i*COPIES*SPACE`**：能保证副本区段不重叠，但运行时
`state` 由 `key.hashCode()` 决定，固定基址会让 case 表与 state 对不上，
全部走 `default` 死循环。已回退。

---

## 七、修掉的 8 个 bug

前 6 个现象完全一样 —— `dx`/`d8` 转不回 dex：

```
dx:  SimException: local 0007: invalid
d8:  NegativeArraySizeException
dex2jar: 方法被替换成 throw new RuntimeException("d2j fail translate: ...")
```

但根因各不相同。真正定位靠 **ASM verifier 给出指令序号**（见第八节）。

### 1. `LBlock` 用了 `org.objectweb.asm2.Label`

fork 内嵌的 `asm2` 与官方 ASM 的 `Label` 不是同一个类，直接 `ClassCastException`。

### 2. `Exprs.nInt()` 创建的 Constant 没补 `valueType`

dex2jar 靠 `TypeTransformer` 在上游流程里统一补。但混淆器是在 IR 转 code
**之前**插新表达式，那些常量没经过 transformer：

```java
// IR2JConverter:1174
String t = constant.valueType;
switch (t.charAt(0))   // ← NPE
```

NPE 被 `Dex2Asm` 捕获后整个方法替换成 throw。

### 3. `FlowObfuscator` 重复 `addAll(newBlock.getStmts())`

外层已加过，内层 `if (nextKey != "")` 又加一遍。体积上看不出来
（`deadCode` transformer 会去重），但带副作用的指令会**执行两次**。

### 4. `newLocal` 的编号与已有 Local 冲突

原实现 `localIndex = ir.locals.size() * 2` 后 `++`。但 `locals.size()`
≠ 最大 `_ls_index`，且三个 chain 各持一个实例、各自重置。

### 5. `newLocal` 没算类型宽度（隐蔽）

`long`/`double` 占 **2 个槽位**。只按 `max + 1` 分配，新 `int` 会落在某个
`long` 的第二个槽上：

```
LLOAD 8 / PUTFIELD MainActivity.E:J
verifier: Expected J, but found .
```

### 6. 槽位复用在 loop head 处的类型合并

平坦化把所有原基本块塞进同一个 `while`，loop head 成了全部路径的汇合点。
只要某个 slot 在部分路径上没被写过，合并结果就退化成 `UNINITIALIZED_VALUE`。

原版那段「给 Local 重新编号 + 插 null 初始化」正是为此。**排查时我曾把它
误判成 bug 删掉**，导致错误在 `local 0005` / `local 0007` 之间反复跳动。

### 7. `lookupswitch` 的 match 键没排序（唯一到运行时才暴露的）

JVM 规范要求 `lookupswitch` 的 match 键**严格升序**。混淆器按插入顺序造键，
正负、大小全随机：

```
java.lang.VerifyError: Bad lookupswitch instruction
```

**为什么前几层验证全没发现：**

| 手段 | 结果 | 原因 |
|---|---|---|
| d8 回转 | ✅ | DEX 的 sparse-switch 不要求有序 |
| dx 回转 | ✅ | 同上 |
| ASM Analyzer | ✅ | 只校验栈帧/类型，不校验 switch 表 |
| **真 JVM 加载** | ❌ `VerifyError` | HotSpot 才校验 |

修法：在 `IR2JConverter` 发射 lookupswitch 时做插入排序。

### 8. 副本展开的 case 值碰撞（静默产错包）

`base + c*SPACE` 在 int 上回绕，两个不同块的 case 值可能撞在一起，
`switchBlock.put` 静默覆盖 → 某块永不可达 → **行为错误**。

实测安全条件：两块基址间距必须 ≥ `COPIES*SPACE`（`0x10000000`）。
现在加了前置探测，有碰撞就整体退化为单份。

---

## 八、验证方法（四层）

光看「命令没报错」不够 —— 翻译失败的方法会被静默替换成
`throw new RuntimeException("d2j fail translate: ...")`，产物 dex 依然「合法」。

1. **ASM verifier**（最精确，直接给出指令序号）
   ```java
   Analyzer<BasicValue> an = new Analyzer<>(new BasicVerifier());
   an.analyze(owner, methodNode);
   ```
   报错形如 `Expected J, but found .`，`.` = `UNINITIALIZED_VALUE`

2. **d8 回转**
   ```bash
   java -Xmx3g -cp d8.jar com.android.tools.r8.D8 --release --output out full.dex
   ```

3. **往返**：`full.dex` → `Dex2jarCmd` → `d8`

4. **真 JVM 加载执行**（唯一能发现运行时错误的一层）

第 4 层的重要性见 bug 7。**中间格式合法（DEX / class 结构）≠ 目标 VM 能接受。**

### 辅助工具

| 工具 | 作用 |
|---|---|
| `Verify` | ASM verifier，逐方法校验栈帧 |
| `SwitchCheck` | 静态扫描所有 lookupswitch 的键顺序 |
| `DeobfHarness` | 5 种反平坦化攻击，输出还原率 |
| `Strength` | 统计块出口的「分支守卫」比例 |
| `Collapse` | 验证 case 副本能否被 `groupBy` 合并 |

---

## 九、升级过程中踩的坑

1. **`compile` → `implementation` 会丢依赖传递** —— 需按需改成 `api`
   并启用 `java-library` 插件
2. **`gradle-wrapper.jar` 可能没进仓库** —— 需单独下载
3. **ANTLR 4.13 对转义更严格** —— `'\"'` 要写成 `'"'`
4. **`applicationDistribution` 在 Gradle 9 只能在 `distributions` 块里访问**
5. **`getRevision()` 这类脚本方法在 `subprojects` 块里不可见**
6. **覆盖上游文件时注意行尾符** —— 上游是 CRLF，本地是 LF，
   `diff` 会显示「全部不同」的假象，用 `diff -wB`

---

## 十、后续方向（如果要继续）

按「能真正改变攻击者成本」排序：

### 1. 字符串加密（最高优先级）

商业版已经验证有效。做法：

```java
// 现在
String url = "https://18comic.vip/";

// 改成（字节码里没有明文）
String url = D.c(KEY_ARRAY, 17, 21, 0x5A3F);
```

`KEY_ARRAY` 是加密的 `int[]` 常量，`c()` 是解密方法。
需要新增一个 Pass：收集所有字符串常量 → 加密成数组 → 注入 `<clinit>` →
生成解密方法 → 替换所有 `LDC`。

**这是唯一能保护业务数据的模块。**

### 2. 去掉块尾明文 key

把状态从「字符串」改成「整数槽位 + 跨类静态字段运算」。
注意：字段初值必须是**编译期确定的常量**（可加密），不能用 `nanoTime`
—— 否则 case 表无法反解。

### 3. 去调试信息 + dex 优化

成本极低，收益立竿见影：删行号表、局部变量名、`nop`、冗余 label。

### 4. 反射保护

关键方法调用改成 `Method.invoke`，切断直接调用图。

### 5. 把 dispatcher 移出 dex

```java
int idx = NativeNext.next(state);   // 表在 .so 里
switch (idx) { case 0: ... }        // case 退化成 0..n-1
```

攻击者看不到「state → 块」的映射。代价：需要 NDK 编译 + JNI 调用开销。
或者走 Dex2C（整个方法体转 native）。

---

## 十一、方法论教训

这是本项目最重要的部分。

### 1. 先写攻击，再写混淆器

前 5 轮全部是「先做变换，再想攻击者会怎么破」，而指标（「抗静态分析 99.2%」）
没有可复现定义。结果是每一轮都能被指出「本质没变」。

正确做法：先把 `DeobfHarness` 的 5 种攻击写好，任何新 Pass 上线前必须
证明它能挡住全部 5 种。

### 2. 「攻击者算不出某个值」≠「攻击者无法还原」

v3/v4 的出发点都是「让攻击者算不出 `state`」。但攻击者根本不经过那一步 ——
他看的是 `case → target` 的映射表，或者块尾的明文 key。

**任何混淆设计都必须先回答：攻击者最短的还原路径是什么？**

### 3. 中间格式合法 ≠ 目标 VM 能接受

`lookupswitch` 键序问题在 d8/dx/ASM 三层全部通过，只有 HotSpot 加载时才炸。

**改写字节码的工具，必须在目标运行时上真跑一遍。**

### 4. 看不懂的「可疑代码」先确认它解决了什么问题

bug 6 里的「给 Local 重新编号」看起来像设计缺陷，实际是让平坦化能被
verifier 接受的唯一手段。删掉后错误在多个位置之间反复跳动，浪费了大量时间。

### 5. 数据保护 > 代码结构保护

本项目 6 个模块里有 5 个在改「代码怎么写」，但攻击者要的是「数据是什么」。
`strings classes.dex | grep http` 依然是成本最低、收益最高的攻击。

---

## 附录：产物位置

| 文件 | 说明 |
|---|---|
| `/data/data/com.termux/files/usr/tmp/device/dexf/classes.dex` | 混淆后的 dex（1,255,296 B） |
| `/data/data/com.termux/files/usr/tmp/device/dexf.jar` | 反解出的 jar，可用 javap/jadx 检查 |
| `/data/data/com.termux/files/usr/tmp/vcls/` | 所有验证/攻击工具的 class |
