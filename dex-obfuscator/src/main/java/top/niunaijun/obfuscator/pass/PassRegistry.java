package top.niunaijun.obfuscator.pass;

import com.googlecode.dex2jar.ir.IrMethod;
import com.googlecode.dex2jar.ir.stmt.Stmt;
import top.niunaijun.obfuscator.ObfuscationPass;
import top.niunaijun.obfuscator.ObfuscatorConfiguration;
import top.niunaijun.obfuscator.chain.FlowObfuscator;
import top.niunaijun.obfuscator.chain.IfObfuscator;
import top.niunaijun.obfuscator.chain.SubObfuscator;
import top.niunaijun.obfuscator.chain.base.ObfuscatorChain;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Pass 编排器。
 *
 * 统一管理「哪些模块参与」「按什么顺序执行」，让每个混淆模块
 * 都能独立开关、独立调试、自由组合。
 *
 * 两阶段模型：
 *
 *   阶段一：chain 列表（逐语句回调）
 *       Flow → If → Sub
 *       这些是从原项目继承的、以「改写单条语句」为基础实现的模块。
 *
 *   阶段二：方法级 Pass（整体重写）
 *       OpaquePredicate / InstructionSubstitution
 *       这些需要看到完整方法体，且必须在 chain 之后执行
 *       （比如不透明谓词要包住平坦化之后的块出口）。
 *
 * 为什么把 OpaquePredicate 放在最后：
 *   它给 IF 前面插恒假分支。若在 Flow 之前插，Flow 会把那些新分支
 *   也拆成基本块，谓词自身反而变成平坦化的一部分，失去「干扰判定」的作用。
 */
public class PassRegistry {

    /** 模块名 -> 是否启用。用 LinkedHashMap 保住声明顺序。 */
    private final Map<String, Boolean> enabled = new LinkedHashMap<>();

    private final List<ObfuscatorChain> chains = new ArrayList<>();
    private final List<ObfuscationPass> methodPasses = new ArrayList<>();

    public PassRegistry(ObfuscatorConfiguration config) {
        int depth = config == null ? 1 : config.getObfDepth();
        int opaqueLayers = config == null ? 2 : config.getOpaqueLayers();
        java.util.Set<String> only = config == null ? null : config.getEnabledModules();

        // ---- 阶段一：chain ----
        addModule("flow", on(only, "flow"), () -> chains.add(new FlowObfuscator(config)));
        addModule("if", on(only, "if"), () -> chains.add(new IfObfuscator(config)));
        addModule("sub", on(only, "sub"), () -> chains.add(new SubObfuscator(config)));

        // ---- 阶段二：方法级 Pass ----
        addModule("instruction-substitution", on(only, "instruction-substitution"),
                () -> methodPasses.add(new InstructionSubstitutionPass(depth)));
        addModule("opaque-predicate", on(only, "opaque-predicate"),
                () -> methodPasses.add(new OpaquePredicatePass(opaqueLayers)));
        // MBA 放在最后：它在最内层表达式上工作，前面所有 Pass 生成的
        // 算术都能被它再混淆一遍。
        addModule("mba", on(only, "mba"),
                () -> methodPasses.add(new MbaSubstitutionPass(depth)));
    }

    /** only 为 null 表示全开；否则只开集合内的。 */
    private static boolean on(java.util.Set<String> only, String name) {
        return only == null || only.contains(name);
    }

    private void addModule(String name, boolean def, Runnable factory) {
        enabled.put(name, def);
        if (def) factory.run();
    }

    /** 运行阶段二的所有 Pass。返回是否发生改动。 */
    public boolean runMethodPasses(IrMethod ir, List<Stmt> stmts) {
        if (methodPasses.isEmpty()) return false;

        ObfuscationPass.IrMethodInfo info = new ObfuscationPass.IrMethodInfo() {
            @Override public String owner() { return ir.owner; }
            @Override public String name() { return ir.name; }
            @Override public String desc() { return ""; }
            @Override public boolean isStatic() { return ir.isStatic; }
            @Override public int trapCount() { return ir.traps.size(); }
            @Override public IrMethod raw() { return ir; }
        };

        List<Stmt> cur = new ArrayList<>(stmts);
        boolean any = false;
        for (ObfuscationPass pass : methodPasses) {
            if (!pass.accept(info)) continue;
            List<Stmt> out = new ArrayList<>(cur.size());
            try {
                if (pass.apply(info, cur, out)) {
                    cur = out;
                    any = true;
                }
            } catch (Throwable t) {
                // 单个模块失败不能拖垮整个方法：回退到这一步之前的语句
                System.err.println("[pass:" + pass.name() + "] " + ir.owner + "->"
                        + ir.name + " 失败，跳过: " + t);
                if (System.getenv("OBF_DEBUG") != null) t.printStackTrace();
            }
        }
        if (any) {
            stmts.clear();
            stmts.addAll(cur);
        }
        return any;
    }

    public List<ObfuscatorChain> chains() {
        return chains;
    }

    public List<ObfuscationPass> methodPasses() {
        return methodPasses;
    }

    /** 当前启用的模块列表，供日志输出。 */
    public String describe() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Boolean> e : enabled.entrySet()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(e.getKey()).append(e.getValue() ? "=on" : "=off");
        }
        return sb.toString();
    }
}
