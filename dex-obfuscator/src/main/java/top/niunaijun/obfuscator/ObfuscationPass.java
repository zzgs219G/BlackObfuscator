package top.niunaijun.obfuscator;

/**
 * 混淆阶段（Pass）。
 *
 * 与 {@link top.niunaijun.obfuscator.chain.base.ObfuscatorChain} 的区别：
 *
 *   ObfuscatorChain  —— 逐【语句】回调，适合改写局部表达式
 *                       （SubObfuscator / IfObfuscator 这类）
 *   ObfuscationPass  —— 对整个【方法】做一次整体重写，方法级前后顺序明确
 *                       （OpaquePredicate / InstructionSubstitution /
 *                         MethodHiding 这类需要看到完整 CFG 的）
 *
 * 拆成两层是因为：方法级的变换（比如平坦化之后再插不透明谓词）必须能
 * 明确表达「我先、你后」，而逐语句回调天然做不到这件事。
 *
 * 每个 Pass 独立开关，互不影响，方便单独调试和自由组合。
 */
public interface ObfuscationPass {

    /** 模块名，用于日志和 CLI 开关。 */
    String name();

    /**
     * 是否处理这个方法。
     *
     * @param ir 方法 IR
     * @return true 表示本 Pass 要处理它
     */
    boolean accept(IrMethodInfo ir);

    /**
     * 对整个方法做一次重写。
     *
     * 实现方直接把新语句写入 out（不要改 orig 的 stmts 列表本身），
     * 返回 true 表示确实改动了（框架据此决定是否替换 ir.stmts）。
     *
     * @param ir   方法 IR
     * @param orig 当前语句列表（只读语义）
     * @param out  输出的语句列表
     * @return 是否发生改动
     */
    boolean apply(IrMethodInfo ir, java.util.List<com.googlecode.dex2jar.ir.stmt.Stmt> orig,
                  java.util.List<com.googlecode.dex2jar.ir.stmt.Stmt> out);

    /** 方法的只读视图，避免各 Pass 直接乱改 IrMethod 的内部状态。 */
    interface IrMethodInfo {
        String owner();

        String name();

        String desc();

        boolean isStatic();

        int trapCount();

        com.googlecode.dex2jar.ir.IrMethod raw();
    }
}
