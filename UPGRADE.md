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

// 新
e2.op2 = Exprs.nSub(v2.getOp1(), Exprs.nInt(-increment), "I");
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

## 四、实测结果（2026-11-27）

用 `JMComic3v2.1.14` 的 classes.dex 测（1,018,520 B，DEX_035）：

| 项 | 结果 |
|---|---|
| 耗时 | **1.5 秒** |
| 产物 | `out.dex` 2,306,380 B |
| 体积变化 | **2.26 倍** |
| 转译失败方法 | 9 个（万级方法里的零头，dex2jar 会写 `*-error.zip` 记录） |

**体积膨胀 2.26× 是平坦化的固有代价** —— 每个基本块要多 3~4 条分发指令
（更新状态码 + goto 回 dispatcher + lookup-switch）。接入流水线前要评估：
一个 69MB 的包全量混淆可能涨到 130MB+。

## 五、已知边界

| 项 | 说明 |
|---|---|
| try-catch 方法不混淆 | `FlowObfuscator` 遇到 `ir.traps.size() > 0` 直接原样返回 |
| `<init>` 不混淆 | 同上，避免构造器语义被破坏 |
| 只处理指定包 | 靠 `-p` / `-a` 过滤，三方库建议排除（README 原文警告） |
| 强度中等 | 状态码是「字符串 hash ^ 随机 index」，块 key 在 dex 里是明文字符串常量，反编译后需手工重建映射 —— 能挡「随手看」，挡不住「愿意花时间的人」 |
| 与 anti-diff 冲突 | 平坦化后 anti-diff 的 E 变换（条件反折）失去意义 |

## 六、升级过程中踩的坑（给后来者）

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
