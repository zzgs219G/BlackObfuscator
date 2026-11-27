package top.niunaijun.obfuscator.pass;

import com.googlecode.dex2jar.ir.IrMethod;
import com.googlecode.dex2jar.ir.expr.*;
import com.googlecode.dex2jar.ir.stmt.*;
import top.niunaijun.obfuscator.ObfuscationPass;
import top.niunaijun.obfuscator.chain.base.BaseObfuscatorChain;

import java.util.*;

/**
 * 模块：不透明谓词（Opaque Predicate）。
 *
 * 目的：让攻击者无法静态判定分支走向，从而无法确定真实控制流边。
 *
 * 种子：Runtime.getRuntime().availableProcessors()
 *   · JVM / ART 规范保证返回值 >= 1，所以 `seed > 0` 运行时恒真
 *   · 静态分析要折叠它，必须先证明这个调用有确定返回值 —— 做不到
 *   · 每个方法只取一次，开销可忽略
 *
 * 处理两类位置：
 *
 *   ① 平坦化的块出口（关键）：
 *          obfStr = nextKey;  goto loopHead;
 *      改为
 *          if (seed > 0) { obfStr = nextKey; }
 *          else          { obfStr = 另一个块的 key; }   ← 运行时永不执行
 *          goto loopHead;
 *      假目标特意选【另一个真实块】而不是新造的死块 —— 否则攻击者
 *      可以用「目标块无人跳入」这种启发式把假边筛掉。
 *
 *   ② 普通条件分支：
 *          if (cond) goto T;
 *      前面插入恒假的 `if (seed < 0) goto next;`，让静态看到两条条件。
 *
 * 独立成 Pass 的原因：需要看到方法完整语句列表才能定位块出口；
 * 且必须能单独关闭（排查控制流问题时先关它，看干净的结构）。
 */
public class OpaquePredicatePass implements ObfuscationPass {

    private static final int MIN_STMTS = 6;

    private final Random random = new Random();

    public OpaquePredicatePass(int depth) {
        // depth 只影响随机强度，不改变正确性
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
        // 收集 loop head：被 goto 指向次数最多的 label
        Map<LabelStmt, Integer> gotoCount = new HashMap<>();
        for (Stmt st : orig) {
            if (st.st == Stmt.ST.GOTO) {
                LabelStmt t = ((GotoStmt) st).target;
                gotoCount.merge(t, 1, Integer::sum);
            }
        }
        LabelStmt loopHead = null;
        int best = 0;
        for (Map.Entry<LabelStmt, Integer> e : gotoCount.entrySet()) {
            if (e.getValue() > best) {
                best = e.getValue();
                loopHead = e.getKey();
            }
        }
        // 没有 loop head 说明没被平坦化，退化成「普通分支插噪声」
        if (loopHead == null || best < 3) {
            return insertBeforeIfs(info, orig, out);
        }

        // 收集所有 "ASSIGN local = ... ; GOTO loopHead" 的块出口，
        // 以及可供选择的假目标 key（同一方法内其它块赋过的字符串）
        List<int[]> exitIdx = new ArrayList<>();
        List<String> allKeys = new ArrayList<>();
        for (int i = 0; i + 1 < orig.size(); i++) {
            Stmt a = orig.get(i), b = orig.get(i + 1);
            if (a.st == Stmt.ST.ASSIGN && b.st == Stmt.ST.GOTO
                    && ((GotoStmt) b).target == loopHead) {
                Stmt.E2Stmt e2 = (Stmt.E2Stmt) a;
                Value v = e2.getOp2();
                if (v.vt == Value.VT.CONSTANT && ((Constant) v).value instanceof String) {
                    allKeys.add((String) ((Constant) v).value);
                    exitIdx.add(new int[]{i, allKeys.size() - 1});
                }
            }
        }
        if (exitIdx.size() < 2) {
            return insertBeforeIfs(info, orig, out);
        }

        Local seed = newSimpleLocal(ir, "opaque_seed", "I");
        Set<Integer> handled = new HashSet<>();
        for (int[] pair : exitIdx) {
            handled.add(pair[0]);
        }

        for (int i = 0; i < orig.size(); i++) {
            if (!handled.contains(i)) {
                out.add(orig.get(i));
                continue;
            }
            Stmt a = orig.get(i);
            Stmt.E2Stmt e2 = (Stmt.E2Stmt) a;
            Local target = (Local) e2.getOp1();
            String realKey = (String) ((Constant) e2.getOp2()).value;

            // 假目标：任一 key 不等于 realKey
            String fakeKey = null;
            for (String k : allKeys) {
                if (!k.equals(realKey)) { fakeKey = k; break; }
            }
            if (fakeKey == null) {
                out.add(a);
                continue;
            }

            LabelStmt realL = newLabel(), deadL = newLabel(), joinL = newLabel();
            // if (seed > 0) 恒真
            out.add(Stmts.nIf(Exprs.nGt(seed, Exprs.nInt(0), "I"), realL));
            out.add(Stmts.nGoto(deadL));

            out.add(realL);
            out.add(Stmts.nAssign(target, stringConst(realKey)));
            out.add(Stmts.nGoto(joinL));

            out.add(deadL);
            out.add(Stmts.nAssign(target, stringConst(fakeKey)));
            out.add(Stmts.nGoto(joinL));

            out.add(joinL);
            // 原语句的下一条是 GOTO loopHead，交给下一轮循环处理
        }

        // 入口初始化 seed
        List<Stmt> head = new ArrayList<>(out.size() + 1);
        head.add(Stmts.nAssign(seed, availableProcessorsCall()));
        head.addAll(out);
        out.clear();
        out.addAll(head);
        ir.locals.add(seed);
        return true;
    }

    /** 没有平坦化结构时：在每个 IF 前插一条恒假分支。 */
    private boolean insertBeforeIfs(IrMethodInfo info, List<Stmt> orig, List<Stmt> out) {
        IrMethod ir = info.raw();
        Local seed = newSimpleLocal(ir, "opaque_seed", "I");
        int n = 0;
        for (Stmt st : orig) {
            if (st.st == Stmt.ST.IF && random.nextBoolean()) {
                LabelStmt skip = newLabel();
                out.add(Stmts.nIf(Exprs.nLt(seed, Exprs.nInt(0), "I"), skip));
                out.add(skip);
                n++;
            }
            out.add(st);
        }
        if (n == 0) return false;
        List<Stmt> head = new ArrayList<>(out.size() + 1);
        head.add(Stmts.nAssign(seed, availableProcessorsCall()));
        head.addAll(out);
        out.clear();
        out.addAll(head);
        ir.locals.add(seed);
        return true;
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
