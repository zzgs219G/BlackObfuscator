package top.niunaijun.obfuscator.pass;

import com.googlecode.dex2jar.ir.IrMethod;
import com.googlecode.dex2jar.ir.expr.*;
import com.googlecode.dex2jar.ir.expr.Value.VT;
import com.googlecode.dex2jar.ir.stmt.*;
import top.niunaijun.obfuscator.ObfuscationPass;
import top.niunaijun.obfuscator.chain.base.BaseObfuscatorChain;

import java.util.*;

/**
 * 模块：不透明谓词（Opaque Predicate）。
 *
 * 目的：让攻击者无法静态判定分支走向，从而无法确定真实控制流边。
 *
 * ## 恒真来源（三个，可叠加）
 *
 *   S1  Runtime.getRuntime().availableProcessors()   —— 规范保证 >= 1
 *   S2  label.length()                               —— 字符串字面量长度恒 >= 1
 *   S3  (seed * k) % k == 0                          —— 算术恒等式
 *
 * 三者都不依赖运行时探测，静态分析要么无法求值（S1 是系统调用）、
 * 要么求值代价远高于收益（S2/S3 需要内联字符串常量、展开乘法）。
 *
 * ## 叠加方式
 *
 *   每个块出口包 N 层（N 由 depth 决定）：
 *
 *       if (S1 > 0) {                    ← 恒真
 *         if (S2 > 0) {                  ← 恒真
 *           obfStr = 真后继的 key;
 *         } else { obfStr = 假目标A; }
 *       } else     { obfStr = 假目标B; }
 *
 *   攻击者要还原这条边，必须同时证明 S1 和 S2 恒真 —— 任一层猜错就
 *   得到错误的前驱块。而且假目标选【另一个真实块】，不能靠
 *   「目标无人跳入」筛掉。
 *
 * ## 为什么独立成 Pass
 *
 * 需要看到方法完整语句列表才能定位块出口；必须能单独关闭
 * （排查控制流问题时先关它看干净结构）。
 */
public class OpaquePredicatePass implements ObfuscationPass {

    private static final int MIN_STMTS = 6;
    private static final int MAX_LAYERS = 3;

    private final Random random = new Random();
    private final int layers;

    public OpaquePredicatePass(int depth) {
        // depth 越大层数越多；限制在 1..3，避免体积爆炸
        this.layers = Math.min(MAX_LAYERS, Math.max(1, depth));
    }

    @Override
    public String name() {
        return "opaque-predicate";
    }

    @Override
    public boolean accept(IrMethodInfo ir) {
        if (ir.trapCount() > 0) return false;
        if ("<init>".equals(ir.name()) || "<clinit>".equals(ir.name())) return false;
        return true;
    }

    @Override
    public boolean apply(IrMethodInfo info, List<Stmt> orig, List<Stmt> out) {
        if (orig.size() < MIN_STMTS) {
            out.addAll(orig);
            return false;
        }

        IrMethod ir = info.raw();

        // ---- 找 loop head：被 goto 指向最多的 label ----
        Map<LabelStmt, Integer> gotoCount = new HashMap<>();
        for (Stmt st : orig) {
            if (st.st == Stmt.ST.GOTO) {
                gotoCount.merge(((GotoStmt) st).target, 1, Integer::sum);
            }
        }
        LabelStmt loopHead = null;
        int best = 0;
        for (Map.Entry<LabelStmt, Integer> e : gotoCount.entrySet()) {
            if (e.getValue() > best) { best = e.getValue(); loopHead = e.getKey(); }
        }
        if (loopHead == null || best < 3) {
            return insertBeforeIfs(info, orig, out);
        }

        // ---- 收集块出口：ASSIGN local = "key" 紧跟 GOTO loopHead ----
        List<Integer> exitPos = new ArrayList<>();
        List<String> allKeys = new ArrayList<>();
        for (int i = 0; i + 1 < orig.size(); i++) {
            Stmt a = orig.get(i), b = orig.get(i + 1);
            if (a.st == Stmt.ST.ASSIGN && b.st == Stmt.ST.GOTO
                    && ((GotoStmt) b).target == loopHead) {
                Value v = ((Stmt.E2Stmt) a).getOp2();
                if (v.vt == Value.VT.CONSTANT && ((Constant) v).value instanceof String) {
                    allKeys.add((String) ((Constant) v).value);
                    exitPos.add(i);
                }
            }
        }
        if (exitPos.size() < 2) {
            return insertBeforeIfs(info, orig, out);
        }

        // ---- 种子：S1 与方法级常量 ----
        Local seedCpu = newSimpleLocal(ir, "op_seed", "I");
        // S2 用一个固定的非空字符串字面量，其 length() 恒 >= 1
        String probe = buildProbeString();
        Local seedLen = newSimpleLocal(ir, "op_len", "I");
        // 注意：Exprs.nLength() 是数组取长度（arraylength），不能用于字符串。
        // 字符串长度必须走 String.length() 虚调用。

        // S3 用的乘数（!= 0）
        int mul = 2 + random.nextInt(997);

        Set<Integer> handled = new HashSet<>(exitPos);
        List<Stmt> body = new ArrayList<>(orig.size() * 2);

        for (int i = 0; i < orig.size(); i++) {
            if (!handled.contains(i)) {
                body.add(orig.get(i));
                continue;
            }
            Stmt.E2Stmt e2 = (Stmt.E2Stmt) orig.get(i);
            Local target = (Local) e2.getOp1();
            String realKey = (String) ((Constant) e2.getOp2()).value;

            // 假目标：任一 key != realKey
            String fakeKey = null;
            for (String k : allKeys) {
                if (!k.equals(realKey)) { fakeKey = k; break; }
            }
            if (fakeKey == null) { body.add(orig.get(i)); continue; }

            emitLayered(body, target, realKey, fakeKey, seedCpu, seedLen, mul);
        }

        // 入口初始化 seedCpu / seedLen
        List<Stmt> head = new ArrayList<>(body.size() + 2);
        head.add(Stmts.nAssign(seedCpu, availableProcessorsCall()));
        head.add(Stmts.nAssign(seedLen, stringLengthCall(probe)));
        head.addAll(body);
        out.clear();
        out.addAll(head);
        ir.locals.add(seedCpu);
        ir.locals.add(seedLen);
        return true;
    }

    /**
     * 发射 N 层嵌套的恒真谓词。
     *
     *   if (S1 > 0) {
     *     if (S2 > 0) {
     *       obfStr = realKey;
     *     } else { obfStr = fakeKey; }
     *   } else { obfStr = fakeKey; }
     *
     * 每层额外加一个假目标（S3 分支），让候选边数随层数指数增长。
     */
    private void emitLayered(List<Stmt> out, Local target, String realKey, String fakeKey,
                             Local seedCpu, Local seedLen, int mul) {
        int n = layers;

        // 为每层准备标签：层 i 的真分支进入层 i+1，假分支落到各自的假目标
        List<LabelStmt> trueLabels = new ArrayList<>();
        List<LabelStmt> falseLabels = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            trueLabels.add(newLabel());
            falseLabels.add(newLabel());
        }
        LabelStmt join = newLabel();
        LabelStmt realAssign = newLabel();

        // ---- 逐层发射条件 ----
        // 第 i 层的真分支落到 trueLabels[i]，紧接着就是第 i+1 层的判断；
        // 最后一层的真分支才跳到 realAssign。
        for (int i = 0; i < n; i++) {
            Value cond;
            switch (i % 3) {
                case 0:
                    // S1: availableProcessors() > 0
                    cond = bin(VT.GT, seedCpu, i32(0), "I");
                    break;
                case 1:
                    // S2: probe.length() > 0
                    cond = bin(VT.GT, seedLen, i32(0), "I");
                    break;
                default:
                    // S3: (seedCpu * mul) % mul == 0 —— 算术恒真
                    cond = bin(VT.EQ,
                            bin(VT.REM, bin(VT.MUL, seedCpu, i32(mul), "I"),
                                    i32(mul), "I"),
                            i32(0), "I");
                    break;
            }
            out.add(Stmts.nIf(cond, trueLabels.get(i)));
            out.add(Stmts.nGoto(falseLabels.get(i)));
            // 真分支落点：下一层的条件从这里开始
            out.add(trueLabels.get(i));
        }
        // 全部为真 → 赋真实 key
        out.add(realAssign);
        out.add(Stmts.nAssign(target, stringConst(realKey)));
        out.add(Stmts.nGoto(join));

        // ---- 各层假分支：赋假 key ----
        for (int i = 0; i < n; i++) {
            out.add(falseLabels.get(i));
            out.add(Stmts.nAssign(target, stringConst(fakeKey)));
            out.add(Stmts.nGoto(join));
        }

        out.add(join);
    }

    /** 没有平坦化结构时：在每个 IF 前插一条恒假分支。 */
    private boolean insertBeforeIfs(IrMethodInfo info, List<Stmt> orig, List<Stmt> out) {
        IrMethod ir = info.raw();
        Local seed = newSimpleLocal(ir, "op_seed", "I");
        Local len = newSimpleLocal(ir, "op_len", "I");
        String probe = buildProbeString();
        int n = 0;
        for (Stmt st : orig) {
            if (st.st == Stmt.ST.IF && random.nextBoolean()) {
                LabelStmt skip = newLabel();
                Value cond = (n % 2 == 0)
                        ? bin(VT.LT, seed, i32(0), "I")       // 恒假
                        : bin(VT.LT, len, i32(0), "I");       // 恒假
                out.add(Stmts.nIf(cond, skip));
                out.add(skip);
                n++;
            }
            out.add(st);
        }
        if (n == 0) return false;
        List<Stmt> head = new ArrayList<>(out.size() + 2);
        head.add(Stmts.nAssign(seed, availableProcessorsCall()));
        head.add(Stmts.nAssign(len, stringLengthCall(probe)));
        head.addAll(out);
        out.clear();
        out.addAll(head);
        ir.locals.add(seed);
        ir.locals.add(len);
        return true;
    }

    /**
     * 生成一个非空字面量，用于 length() >= 1 恒真判断。
     * 用非 ASCII 字符避免被 dex2jar 的常量池优化合并成常见字符串。
     */
    private String buildProbeString() {
        StringBuilder sb = new StringBuilder();
        int n = 3 + random.nextInt(5);
        for (int i = 0; i < n; i++) {
            sb.append((char) (0x4E00 + random.nextInt(0x5000)));
        }
        return sb.toString();
    }

    /**
     * 构造一个二元表达式并补上 valueType。
     *
     * ⚠️ BinopExpr 把类型存在 `type` 字段，而 IR2JConverter 读的是 `valueType`：
     *     reBuildJumpInstructions -> v1.valueType.charAt(0)
     * 只设 type 会让 valueType 为 null → 转换时 NPE。
     * 两处都要设。
     */
    /**
     * 构造整型常量并补 valueType。
     *
     * ⚠️ IR2JConverter.reBuildE2Expression 第一行就是
     *     String type = e2.op2.valueType;
     * 然后 getOpcode(type, ...) 里 type.charAt(0)。
     * i32() 创建的 Constant 不设 valueType → 直接 NPE。
     */
    private static Constant i32(int v) {
        Constant c = Exprs.nInt(v);
        c.valueType = "I";
        return c;
    }

    private static BinopExpr bin(VT vt, Value a, Value b, String type) {
        BinopExpr e;
        switch (vt) {
            case GT:  e = Exprs.nGt(a, b, type); break;
            case LT:  e = Exprs.nLt(a, b, type); break;
            case EQ:  e = Exprs.nEq(a, b, type); break;
            case NE:  e = Exprs.nNe(a, b, type); break;
            case MUL: e = Exprs.nMul(a, b, type); break;
            case REM: e = Exprs.nRem(a, b, type); break;
            default:  throw new IllegalArgumentException("unsupported: " + vt);
        }
        e.valueType = type;
        return e;
    }

    /** s.length()，返回值恒 >= 1（s 是字面量）。 */
    private InvokeExpr stringLengthCall(String s) {
        return Exprs.nInvokeVirtual(new Value[]{Exprs.nString(s)},
                "Ljava/lang/String;", "length", new String[]{}, "I");
    }

    private Constant stringConst(String s) {
        Constant c = Exprs.nString(s);
        c.valueType = "Ljava/lang/String;";
        return c;
    }

    public static InvokeExpr availableProcessorsCall() {
        return Exprs.nInvokeVirtual(
                new Value[]{Exprs.nInvokeStatic(new Value[]{}, "Ljava/lang/Runtime;",
                        "getRuntime", new String[]{}, "Ljava/lang/Runtime;")},
                "Ljava/lang/Runtime;", "availableProcessors", new String[]{}, "I");
    }

    private Local newSimpleLocal(IrMethod ir, String name, String type) {
        int next = 0;
        for (Local l : ir.locals) {
            if (l._ls_index < 0) continue;
            int end = l._ls_index + BaseObfuscatorChain.slotWidth(l.valueType);
            if (end > next) next = end;
        }
        Local local = Exprs.nLocal(next, name);
        local.valueType = type;
        return local;
    }

    private LabelStmt newLabel() {
        LabelStmt ls = Stmts.nLabel();
        ls.tag = new org.objectweb.asm.Label();
        return ls;
    }
}
