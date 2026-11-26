# 升级记录（2026-11-27）

本 fork 从原版（2025-05）升级到现代工具链。

## 一、升级内容

| 依赖 | 升级前 | 升级后 |
|---|---|---|
| Gradle | 6.9.1（2021） | **9.9.2**（2026-11） |
| Java | 8 | **17** |
| dex2jar | 2.1-SNAPSHOT（2012 代码底子） | **2.4**（2026-10） |
| ASM | 内嵌 `org.objectweb.asm2`（2012 fork） | **org.ow2.asm 9.11.1**（官方） |
| guava | 18.0（2014） | **33.8.0-jre** |
| antlr4-runtime | 4.5 | **4.13.2** |
| junit | 4.10 / 4.11 / 4.12 | **5.11.4** |
| baksmali | 2.0.6 | **2.5.2** |
| commons-compress | 1.4.1 | **1.28.0** |

### 关键收益：支持 DEX_039 / DEX_040

原版只认 `DEX_035 ~ DEX_038`，遇到 Android 9+ 用 R8 编译的包（DEX_039）
直接抛 `not support version`。现在上限放宽到 `DEX_040`，且改为
「不认识的版本继续尝试」而非直接抛异常。

## 二、改了什么

### 1. 构建脚本（Gradle 9 语法）

| 老写法（Gradle 6 及以前） | 新写法（Gradle 9） |
|---|---|
| `apply plugin: 'maven'` | 已移除，不再需要发布到本地 maven |
| `apply plugin: 'idea'/'eclipse'` | 已移除（IDE 自己负责） |
| `compile project(...)` | `api project(...)` / `implementation project(...)` |
| `compile 'g:a:v'` | `implementation 'g:a:v'` |
| `sourceCompatibility = 1.8` | `JavaVersion.VERSION_17` |
| `task xxx(type: JavaExec)` | `tasks.register('xxx', JavaExec)` |
| `mainClassName = "..."` | `application { mainClass = "..." }` |
| `artifacts.archives distZip` | 已移除（用 `distZip` 任务直接跑） |

⚠️ **`api` 与 `implementation` 的区别很重要**：`compile` 会传递依赖，
`implementation` 不会。原代码里 `d2j-smali` 依赖 `dex-reader` 却直接用
`dex-reader-api` 的类，改成 `implementation` 后会编译失败。所以需要传递的
依赖一律用 `api`，并启用 `java-library` 插件。

### 2. dex2jar 2.1 → 2.4（上游覆盖）

覆盖了这些模块（本 fork 没改过）：
`dex-reader` / `dex-reader-api` / `dex-writer` / `dex-ir` / `dex-translator` /
`d2j-base-cmd` / `d2j-jasmin` / `d2j-smali`

**保留了本 fork 的三处注入**（重新打补丁）：
- `dex-translator/.../IR2JConverter.java` —— `obf` 字段 + `reBuildInstructions` 里调 `IRObfuscator`
- `dex-translator/.../Dex2jar.java` —— `obf()` builder，传给 `IR2JConverter`
- `dex-tools/.../Dex2jarCmd.java` —— `Dex2jarCmd(ObfuscatorConfiguration)` 构造器

### 3. asm2 → 官方 ASM

上游 v2.4 全面改用 `org.ow2.asm`，不再内嵌 `asm2`。同步改动：
- `d2j-jasmin/src/main/antlr3/.../Jasmin.g` 的 import
- `d2j-smali/src/main/antlr4/.../Smali.g4` 的 import + `method_handler` 规则

### 4. 修 `Value.vt` 变 final

dex2jar 2.4 把 `Value.vt` 改成 `final`，`SubObfuscator.java` 里两处
`v2.vt = Value.VT.SUB/ADD` 编译不过。改为构造新表达式替换整个 `e2.op2`：

```java
// 旧
v2.vt = Value.VT.SUB;
v2.setOp2(Exprs.nInt(-increment));

// 新 —— 注意必须补 valueType，否则 IR2JConverter NPE（见第六节 bug 2）
Constant c = Exprs.nInt(-increment);
c.valueType = "I";
e2.op2 = Exprs.nSub(v2.getOp1(), c, "I");
```

### 5. 精简 `dex-tools`

删掉 30 个用不到的 CLI 工具，只保留混淆链路需要的：
`BlackObfuscatorCmd` / `Dex2jarCmd` / `Jar2Dex` / `BaksmaliBaseDexExceptionHandler`

**原因**：`SunJarSignImpl` 用了 `sun.security.pkcs/x509`（JDK 17+ 已封装为不可访问），
而那些 signapk / weaver 工具与本项目无关。

### 6. `Main.java` 改为真 CLI

原来硬编码作者本机路径 `/Users/milk/Documents/classes.dex`，现在透传命令行参数。

## 三、怎么用

### 编译

```bash
./gradlew build -x test          # 产出各模块 jar
```

### 运行

```bash
# classpath = 本工程所有 jar + 依赖
CP=$(find . -name "*.jar" -path "*libs*" | tr '\n' ':')
CP="$CP$(find ~/.gradle/caches -name 'guava-33.8.0-jre.jar' \
  -o -name 'asm-9.11.1.jar' -o -name 'asm-tree-9.11.1.jar' \
  -o -name 'asm-util-9.11.1.jar' -o -name 'asm-analysis-9.11.1.jar' \
  -o -name 'asm-commons-9.11.1.jar' -o -name 'antlr4-runtime-4.13.2.jar' \
  -o -name 'antlr-runtime-3.5.3.jar' 2>/dev/null | tr '\n' ':')"

java -cp "$CP" com.googlecode.dex2jar.tools.BlackObfuscatorCmd \
  -d 2 -i classes.dex -o out.dex -p com.example x
```

> ⚠️ 末尾那个 `x` 是**必须的占位参数**：`BlackObfuscatorCmd` 里有一句
> `if (remainingArgs.length == 0) { usage(); return; }`，不给位置参数就只打
> usage 不干活。

> `-p` 是**白名单**（只混淆这个包），不是黑名单；`splitDex` 的 `whiteList`
> 为空会直接返回 0、什么都不做。想排除某个包用 `-a` 传 allowList 文件。

排错时加 `-k`（`--keep`）保留中间产物：

```bash
java -cp "$CP" com.googlecode.dex2jar.tools.BlackObfuscatorCmd \
  -d 2 -i classes.dex -o out.dex -p com.example -k x
# keep: split=/tmp/xxxsplit.dex    ← 从原 dex 切出来的待混淆部分
# keep: jar=/tmp/xxxobf.jar        ← 混淆后的 class，可用 javap 检查
# keep: dex=/tmp/xxxobf.dex        ← 混淆后的片段 dex，会被合回 out.dex
```

`obf.jar` 是排查主要抓手 —— 用 `javap -p -c` 看方法体是
`throw new RuntimeException("d2j fail translate: ...")` 还是真的被平坦化了。

## 四、实测结果（2026-11-27）

用 `JMComic3v2.1.14` 的 classes.dex 测（1,018,520 B，DEX_035）：

| 项 | 结果 |
|---|---|
| 耗时 | **1.5 秒** |
| 产物 | `out.dex` 2,347,336 B |
| 体积变化 | **2.30 倍** |
| 转译失败方法 | **0** |
| ASM verifier 失败 | **0** |
| d8 回转 dex | ✅ 0 error（1,057,792 B） |
| dex2jar 反解 → d8 | ✅ 0 error（1,040,920 B） |

**体积膨胀 2.3× 是平坦化的固有代价** —— 每个基本块要多 3~4 条分发指令
（更新状态码 + goto 回 dispatcher + lookup-switch）。接入流水线前要评估：
一个 69MB 的包全量混淆可能涨到 160MB+。

### 验证手段

光看「命令没报错」不够 —— `BlackObfuscatorCmd` 会把翻译失败的方法
静默替换成 `throw new RuntimeException("d2j fail translate: ...")`，
产物 dex 依然是「合法」的，装到机器上才炸。建议三层验证：

1. **ASM verifier**（最精确，直接给出指令序号）
   `Analyzer(new BasicVerifier()).analyze(owner, methodNode)`
   报错形如 `Expected J, but found .`，`.` = `UNINITIALIZED_VALUE`
2. **d8 回转**：`java -Xmx3g -cp d8.jar com.android.tools.r8.D8 --release --output out full.dex`
3. **往返**：`full.dex` → `Dex2jarCmd` → `d8`，确认能二次转回

## 五、已知边界

| 项 | 说明 |
|---|---|
| try-catch 方法不混淆 | `FlowObfuscator` 遇到 `ir.traps.size() > 0` 直接原样返回 |
| `<init>` 不混淆 | 同上，避免构造器语义被破坏 |
| 只处理指定包 | 靠 `-p` / `-a` 过滤，三方库建议排除（README 原文警告） |
| 强度中等 | 状态码是「字符串 hash ^ 随机 index」，块 key 在 dex 里是明文字符串常量，反编译后需手工重建映射 —— 能挡「随手看」，挡不住「愿意花时间的人」 |
| 与 anti-diff 冲突 | 平坦化后 anti-diff 的 E 变换（条件反折）失去意义 |

## 六、修掉的 6 个 bug（平坦化产出非法字节码）

这 6 个 bug 的**现象完全一样** —— `dx`/`d8` 转不回 dex：

```
dx:  SimException: local 0007: invalid
d8:  NegativeArraySizeException: -384128459
dex2jar: 方法被替换成 throw new RuntimeException("d2j fail translate: ...")
```

但根因各不相同，逐个靠「改一版、跑一遍」看不出方向。真正定位靠
**ASM verifier 给出指令序号**（见上一节的验证手段）。

### 1. `LBlock` 用了 `org.objectweb.asm2.Label`

fork 内嵌的 `asm2` 与官方 ASM 9 的 `Label` 不是同一个类，类型转换直接
`ClassCastException`。升级到官方 ASM 后统一改用 `org.objectweb.asm.Label`。

### 2. `SubObfuscator` 里 `Exprs.nInt()` 没补 `valueType`

`Constant` 的构造器**不设置** `valueType` —— dex2jar 靠 `TypeTransformer`
在上游正常流程里统一补（`TypeTransformer.java:94`）。混淆器是**在 IR 转
code 之前**插新表达式，那些常量没经过 transformer，`valueType` 为 null：

```java
// IR2JConverter:1174
String t = constant.valueType;
switch (t.charAt(0))   // ← NPE
```

NPE 被 `Dex2Asm` 捕获后整个方法替换成 throw。修法是显式赋值：
`c.valueType = "I"`。

### 3. `FlowObfuscator` 重复 `addAll(newBlock.getStmts())`

外层已经加过一遍，内层 `if (nextKey != "")` 分支又加一遍 —— 每个带后继的
基本块，指令在字节码里出现两遍。体积上看不出来（`deadCode` transformer
会去重），但带副作用的指令（方法调用、字段写入）会被**执行两次**，改变
程序行为。

### 4. `newLocal` 的编号与已有 Local 冲突

原实现：

```java
localIndex = ir.locals.size() * 2;          // reBuild 时重置
Local local = Exprs.nLocal(++localIndex, name);
```

两个问题：`locals.size()` ≠ 最大 `_ls_index`；且 `Flow`/`Sub`/`If` 三个
chain 各持一个实例、各自重置 → 分到同一批编号。改成扫当前最大值。

### 5. `newLocal` 没算类型宽度（**这是最隐蔽的一个**）

`long` / `double` 在 JVM 里占 **2 个槽位**。只按 `max + 1` 分配，一个新
`int` 会正好落在某个 `long` 的第二个槽上，把那个 `long` 直接拆坏：

```
LLOAD 8
PUTFIELD MainActivity.E:J
verifier: Expected J, but found .
```

dex2jar 自己的 `Ir2JRegAssignTransformer` 是按宽度着色的
（`excludeColor.get(i) && excludeColor.get(i + 1)`），这里必须保持一致：

```java
int end = l._ls_index + slotWidth(l.valueType);   // J/D 算 2
```

### 6. 槽位复用在 loop head 处的类型合并（**这才是主因**）

平坦化把所有原基本块塞进同一个 `while`，**loop head 成了全部路径的汇合点**。
verifier 在该点对每个 slot 做类型合并 —— 只要某个 slot 在**部分路径上没被
写过**，合并结果就退化成 `UNINITIALIZED_VALUE`。

原版 `FlowObfuscator` 那段看起来可疑的代码正是为此：

```java
local1._ls_index = newLocal("new_local", op2.valueType)._ls_index;
newStmts.add(Stmts.nAssign(local1, getNullValue(op2)));
```

- 前半句：给每个被赋值的局部变量分配**独占**槽位 —— 原 dex 里同一个寄存器
  会承载不同类型的不同变量，平坦化后这些变量在 loop head 汇合，类型必然冲突
- 后半句：在**方法入口（while 之前）** 插一条初始化为 0/null 的赋值 —— 让
  每个槽位在所有路径上都已初始化，合并结果才有定义

**排查过程中我把这段当成 bug 删掉过**，结果错误从 `local 0005` 变成
`local 0007`，一直找不到方向。教训：看不懂的「可疑代码」先确认它解决了
什么问题，再判断是不是 bug。

## 七、升级过程中踩的坑（给后来者）

1. **`compile` → `implementation` 会丢依赖传递** —— 必须按需改成 `api`
   并启用 `java-library` 插件，否则一堆「cannot find symbol」
2. **`gradle-wrapper.jar` 可能没进仓库** —— 需要单独下载
   `https://raw.githubusercontent.com/gradle/gradle/v<ver>/gradle/wrapper/gradle-wrapper.jar`
3. **ANTLR 4.13 对转义更严格** —— `'\"'` 要写成 `'"'`
4. **`applicationDistribution` 在 Gradle 9 只能在 `distributions` 块里访问**
5. **`getRevision()` 这类脚本方法在 `subprojects` 块里不可见** —— 要提到前面
   定义成闭包变量
6. **覆盖上游文件时要注意行尾符** —— 上游是 CRLF，本地是 LF，`diff` 会显示
   「全部不同」的假象，用 `diff -wB` 才看得到真实差异
