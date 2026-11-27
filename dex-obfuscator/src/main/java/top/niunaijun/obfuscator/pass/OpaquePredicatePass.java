package top.niunaijun.obfuscator.pass;

import com.googlecode.dex2jar.ir.IrMethod;
import com.googlecode.dex2jar.ir.Trap;
import com.googlecode.dex2jar.ir.expr.*;
import com.googlecode.dex2jar.ir.expr.Value.VT;
import com.googlecode.dex2jar.ir.stmt.*;
import top.niunaijun.obfuscator.ObfuscationPass;
import top.niunaijun.obfuscator.chain.base.BaseObfuscatorChain;

import java.util.*;

/**
 * 模块：不透明谓词（Opaque Predicate）。
 *
 * ## 为什么重写
 *
 * 第一版用的是 `Runtime.getRuntime().availableProcessors() > 0` 这类谓词，
 * 实测被攻击者 89.5% 折叠 —— 因为它是一个【固定的、可 grep 的 API 调用】，
 * 攻击者写三条规则就能全部剪掉。那不是不透明，只是把常量换了写法。
 *
 * ## 现在用什么
 *
 * 用【数论恒等式】，且把变量绑定到方法里真实存在的运行时值（anchor），
 * 而不是自己造一个自足的常量。
 *
 * 三条恒真式（对任意 int x 都成立，含 Java 溢出语义）：
 *
 *   P1  (x * (x + 1)) % 2 == 0
 *       x 与 x+1 必有一偶，乘积必偶。
 *       溢出情形：x = MAX 时 x+1 = MIN（偶数），x 为奇数，乘积仍为偶。
 *       取模：偶数 % 2 == 0 对负数同样成立。
 *
 *   P2  (x | 1) != 0
 *       x|1 必为奇数，奇数不可能为 0。
 *
 *   P3  (x ^ (x >> 31)) >= 0
 *       x>>31 对非负得 0、对负得 -1。
 *       x^0 = x >= 0；x^-1 = ~x = -x-1 >= 0（含 MIN→MAX）。
 *
 * 三者都需要「知道具体数学性质」才能折叠，而不是认出一个 API 名字。
 * 用符号执行 + 定理证明仍可破，但成本比 grep 高一个量级。
 *
 * ## anchor 为什么关键
 *
 * 若 x 是编译期常量，上述三式会被常量折叠直接算出来。所以必须绑定一个
 * 攻击者无法静态定值的量：
 *   ① 优先用方法已有的 int 局部变量（参数最佳）—— 攻击者必须追数据流
 *   ② 没有可用 int 时，退回 availableProcessors()（弱，但聊胜于无）
 *
 * ## 语义安全
 *
 * 三条式子恒真 ⇒ else 分支永不执行 ⇒ 只把 obfStr 赋成"另一个真实块的 key"
 * 这段死代码永远跑不到。语义不变由数论保证，不依赖任何运行时探测。
 */
public class OpaquePredicatePass implements ObfuscationPass {

    private static final int MIN_STMTS = 6;
    private static final int MAX_LAYERS = 4;
    /** 可用的数论恒真式数量（P1/P2/P3），层数按此循环选取。 */
    private static final int COND_COUNT = 3;

    private final Random random = new Random();
    private final int layers;

    public OpaquePredicatePass(int depth) {
        this.layers = Math.min(MAX_LAYERS, Math.max(1, depth));
    }

    @Override
    public String name() {
        return "opaque-predicate";
    }

    @Override
    public boolean accept(IrMethodInfo ir) {
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
        Set<Integer> trapRange = trapCoveredIndices(info, orig);

        // anchor：只用参数或新造并初始化的 slot（见 pickAnchor 说明）
        List<Stmt> head = new ArrayList<>();
        Local anchor = pickAnchor(ir, head);

        // ---- 找 loop head ----
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
            boolean changed = insertBeforeIfs(orig, out, trapRange, anchor);
            if (changed) injectHead(out, head);
            return changed;
        }

        // ---- 收集块出口 ----
        List<Integer> exitPos = new ArrayList<>();
        List<String> allKeys = new ArrayList<>();
        for (int i = 0; i + 1 < orig.size(); i++) {
            Stmt a = orig.get(i), b = orig.get(i + 1);
            if (a.st == Stmt.ST.ASSIGN && b.st == Stmt.ST.GOTO
                    && ((GotoStmt) b).target == loopHead) {
                Value v = ((Stmt.E2Stmt) a).getOp2();
                if (v.vt == Value.VT.CONSTANT && ((Constant) v).value instanceof String) {
                    allKeys.add((String) ((Constant) v).value);
                    if (!trapRange.contains(i)) exitPos.add(i);
                }
            }
        }
        if (exitPos.size() < 2) {
            boolean changed = insertBeforeIfs(orig, out, trapRange, anchor);
            if (changed) injectHead(out, head);
            return changed;
        }

        Set<Integer> handled = new HashSet<>(exitPos);
        for (int i = 0; i < orig.size(); i++) {
            if (!handled.contains(i)) {
                out.add(orig.get(i));
                continue;
            }
            Stmt.E2Stmt e2 = (Stmt.E2Stmt) orig.get(i);
            Local target = (Local) e2.getOp1();
            String realKey = (String) ((Constant) e2.getOp2()).value;
            String fakeKey = null;
            for (String k : allKeys) {
                if (!k.equals(realKey)) { fakeKey = k; break; }
            }
            if (fakeKey == null) { out.add(orig.get(i)); continue; }
            emitLayered(out, target, realKey, fakeKey, anchor);
        }
        injectHead(out, head);
        return true;
    }

    /** 把 anchor 初始化语句插到方法入口。 */
    private void injectHead(List<Stmt> out, List<Stmt> head) {
        if (head.isEmpty()) return;
        List<Stmt> merged = new ArrayList<>(out.size() + head.size());
        merged.addAll(head);
        merged.addAll(out);
        out.clear();
        out.addAll(merged);
    }

    /**
     * 发射 N 层数论恒真谓词。
     *
     *   if (P1) { if (P2) { ... { obfStr = realKey; }
     *                       else { obfStr = fakeKey; } }
     *             else { obfStr = fakeKey; } }
     *   else    { obfStr = fakeKey; }
     */
    private void emitLayered(List<Stmt> out, Local target, String realKey, String fakeKey,
                             Local x) {
        int n = layers;
        List<LabelStmt> trueL = new ArrayList<>();
        List<LabelStmt> falseL = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            trueL.add(newLabel());
            falseL.add(newLabel());
        }
        LabelStmt join = newLabel();

        // 逐层发射条件。第 i 层的真分支落点 trueL[i] 就直接是
        // 第 i+1 层的条件起点（最后一层则落到真实赋值处），
        // 因此不需要额外的 realAssign 标签 —— 否则会多一条无用 GOTO。
        for (int i = 0; i < n; i++) {
            Value cond;
            switch (i % COND_COUNT) {
                case 0:
                    // P1: (x * (x+1)) % 2 == 0
                    cond = bin(VT.EQ,
                            bin(VT.REM, bin(VT.MUL, x, bin(VT.ADD, x, i32(1), "I"), "I"),
                                    i32(2), "I"),
                            i32(0), "I");
                    break;
                case 1:
                    // P2: (x | 1) != 0
                    cond = bin(VT.NE, bin(VT.OR, x, i32(1), "I"), i32(0), "I");
                    break;
                default:
                    // P3: (x ^ (x >> 31)) >= 0
                    cond = bin(VT.GE,
                            bin(VT.XOR, x, bin(VT.SHR, x, i32(31), "I"), "I"),
                            i32(0), "I");
                    break;
            }
            out.add(Stmts.nIf(cond, trueL.get(i)));
            out.add(Stmts.nGoto(falseL.get(i)));
            out.add(trueL.get(i));
        }
        out.add(Stmts.nAssign(target, stringConst(realKey)));
        out.add(Stmts.nGoto(join));

        for (int i = 0; i < n; i++) {
            out.add(falseL.get(i));
            out.add(Stmts.nAssign(target, stringConst(fakeKey)));
            out.add(Stmts.nGoto(join));
        }
        out.add(join);
    }

    /** 没平坦化结构时：每个可插入的 IF 前加一条数论恒假分支。 */
    private boolean insertBeforeIfs(List<Stmt> orig, List<Stmt> out,
                                    Set<Integer> trapRange, Local anchor) {
        int n = 0;
        for (int idx = 0; idx < orig.size(); idx++) {
            Stmt st = orig.get(idx);
            if (st.st == Stmt.ST.IF && !trapRange.contains(idx) && random.nextBoolean()) {
                LabelStmt skip = newLabel();
                // 恒假：(x * (x+1)) % 2 != 0 —— 永假，所以永远跳过
                Value cond = bin(VT.NE,
                        bin(VT.REM, bin(VT.MUL, anchor,
                                bin(VT.ADD, anchor, i32(1), "I"), "I"),
                                i32(2), "I"),
                        i32(0), "I");
                out.add(Stmts.nIf(cond, skip));
                out.add(skip);
                n++;
            }
            out.add(st);
        }
        return n > 0;
    }

    /**
     * 选一个攻击者无法静态定值的 int anchor。
     *
     * 优先用方法已有的 int 局部变量（参数更佳：来自调用方，静态更不可知）。
     * 一个都用不到时退回 availableProcessors() —— 那个弱，但好过没有。
     */
    /**
     * 选一个攻击者无法静态定值、且【进入循环前必然已初始化】的 int anchor。
     *
     * ⚠️ 只认参数，不认普通局部变量。
     * 普通局部变量在 loop head 处可能尚未赋值 —— 平坦化把 loop head 变成
     * 全部路径的汇合点，verifier 在该点做类型合并时，未初始化的 slot 会
     * 退化为 UNINITIALIZED_VALUE：
     *     dx: SimException: local 0043: invalid
     *     d8: NegativeArraySizeException
     * 参数由 JVM 保证入口已初始化，是唯一安全的选择。
     *
     * 没有 int 参数时，新造一个 slot 并在方法入口赋
     * availableProcessors()（值 >= 1，恒真且静态不可折叠）。
     */
    private Local pickAnchor(IrMethod ir, List<Stmt> head) {
        int slot = ir.isStatic ? 0 : 1;
        if (ir.args != null) {
            for (String argType : ir.args) {
                if ("I".equals(argType)) {
                    for (Local l : ir.locals) {
                        if (l._ls_index == slot && "I".equals(l.valueType)) {
                            return l;
                        }
                    }
                }
                slot += ("J".equals(argType) || "D".equals(argType)) ? 2 : 1;
            }
        }
        // 没有 int 参数：新造 slot 并在方法入口初始化
        Local fresh = newLocal(ir, "op_anchor", "I");
        head.add(Stmts.nAssign(fresh, Exprs.nInvokeVirtual(
                new Value[]{Exprs.nInvokeStatic(new Value[]{}, "Ljava/lang/Runtime;",
                        "getRuntime", new String[]{}, "Ljava/lang/Runtime;")},
                "Ljava/lang/Runtime;", "availableProcessors", new String[]{}, "I")));
        return fresh;
    }

    private Set<Integer> trapCoveredIndices(IrMethodInfo info, List<Stmt> orig) {
        Set<Integer> out = new HashSet<>();
        IrMethod ir = info.raw();
        if (ir.traps.isEmpty()) return out;
        Map<LabelStmt, Integer> labelIdx = new HashMap<>();
        for (int i = 0; i < orig.size(); i++) {
            if (orig.get(i).st == Stmt.ST.LABEL) labelIdx.put((LabelStmt) orig.get(i), i);
        }
        for (Trap t : ir.traps) {
            Integer s = labelIdx.get(t.start), e = labelIdx.get(t.end);
            if (s != null && e != null) {
                for (int i = s; i < e && i < orig.size(); i++) out.add(i);
            }
            if (t.handlers != null) {
                for (LabelStmt h : t.handlers) {
                    Integer hi = labelIdx.get(h);
                    if (hi != null) out.add(hi);
                }
            }
        }
        return out;
    }

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
            case GE:  e = Exprs.nGe(a, b, type); break;
            case LE:  e = Exprs.nLe(a, b, type); break;
            case EQ:  e = Exprs.nEq(a, b, type); break;
            case NE:  e = Exprs.nNe(a, b, type); break;
            case MUL: e = Exprs.nMul(a, b, type); break;
            case REM: e = Exprs.nRem(a, b, type); break;
            case ADD: e = Exprs.nAdd(a, b, type); break;
            case SUB: e = Exprs.nSub(a, b, type); break;
            case OR:  e = Exprs.nOr(a, b, type); break;
            case AND: e = Exprs.nAnd(a, b, type); break;
            case XOR: e = Exprs.nXor(a, b, type); break;
            case SHR: e = Exprs.nShr(a, b, type); break;
            default:  throw new IllegalArgumentException("unsupported: " + vt);
        }
        e.valueType = type;
        return e;
    }

    private Constant stringConst(String s) {
        Constant c = Exprs.nString(s);
        c.valueType = "Ljava/lang/String;";
        return c;
    }

    /** 新建 local 并立刻登记（否则连续两次调用会拿到同一槽位）。 */
    private Local newLocal(IrMethod ir, String name, String type) {
        int next = 0;
        for (Local l : ir.locals) {
            if (l._ls_index < 0) continue;
            int end = l._ls_index + BaseObfuscatorChain.slotWidth(l.valueType);
            if (end > next) next = end;
        }
        Local local = Exprs.nLocal(next, name);
        local.valueType = type;
        ir.locals.add(local);
        return local;
    }

    private LabelStmt newLabel() {
        LabelStmt ls = Stmts.nLabel();
        ls.tag = new org.objectweb.asm.Label();
        return ls;
    }
}
