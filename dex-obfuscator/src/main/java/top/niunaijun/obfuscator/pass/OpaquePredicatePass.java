package top.niunaijun.obfuscator.pass;

import com.googlecode.dex2jar.ir.IrMethod;
import com.googlecode.dex2jar.ir.Trap;
import com.googlecode.dex2jar.ir.expr.*;
import com.googlecode.dex2jar.ir.expr.Value.VT;
import top.niunaijun.obfuscator.ObfuscationPass;
import top.niunaijun.obfuscator.chain.base.BaseObfuscatorChain;
import com.googlecode.dex2jar.ir.stmt.*;

import java.util.*;

/**
 * 模块：不透明谓词（Opaque Predicate）。
 *
 * ## 演进过程（记录踩过的坑，避免再犯）
 *
 * v1  `availableProcessors() > 0`
 *     → 固定 API 调用，grep 三条正则全折。实测存活 10.5%。
 *
 * v2  三条数论恒等式，但所有块用同一组、固定嵌套顺序
 *     → jadx 反编译后每个块出口长得一模一样，成了指纹：
 *         if (((x+1)*x) % 2 != 0) { A } else if ((x|1) != 0) { B } else { C }
 *       攻击者认出一次就全局替换。
 *
 * v3（本版）
 *     · 谓词池扩到 {@link IdentityPool#SIZE} 种，每个块【随机抽取】
 *       不同形式、不同层数、不同顺序
 *     · 每层的假目标独立随机（原来是同一个），制造真正的扇出
 *     · anchor 优先级：int 参数 > 方法内已有 int 局部 > 运行时派生值
 *
 * ## 为什么用数论恒等式而不是「系统调用恒真」
 *
 * `availableProcessors() >= 1` 这类，人一眼就知道，静态分析也能直接代入。
 * 而数论恒等式要求证明者对【任意 int】成立，必须用具体数学性质：
 *
 *     (x*(x+1)) % 2 == 0      x 与 x+1 必有一偶（含溢出）
 *     (x|1) != 0              x|1 为奇数
 *     (x ^ (x>>31)) >= 0      符号位被消掉
 *
 * 想全部折叠，攻击者必须上符号执行 + 位向量求解（Z3/angr），
 * 成本从「读代码」抬到「跑专业工具」。
 *
 * ## 语义安全
 *
 * 所有谓词对任意 int 恒真 ⇒ else 分支永不执行 ⇒
 * 死代码只把状态变量赋成另一个真实块的 key，永远跑不到。
 * 语义不变由数论保证，不依赖任何运行时探测。
 */
public class OpaquePredicatePass implements ObfuscationPass {

    private static final int MIN_STMTS = 6;

    private final Random random = new Random();
    private final int maxLayers;

    public OpaquePredicatePass(int layers) {
        this.maxLayers = Math.max(1, Math.min(4, layers));
    }

    @Override
    public String name() {
        return "opaque-predicate";
    }

    @Override
    public boolean accept(IrMethodInfo ir) {
        return !"<init>".equals(ir.name()) && !"<clinit>".equals(ir.name());
    }

    @Override
    public boolean apply(IrMethodInfo info, List<Stmt> orig, List<Stmt> out) {
        if (orig.size() < MIN_STMTS) {
            out.addAll(orig);
            return false;
        }
        IrMethod ir = info.raw();
        Set<Integer> trapRange = trapCoveredIndices(info, orig);

        List<Stmt> head = new ArrayList<>();
        Local anchor = pickAnchor(ir, head);

        // 找 dispatcher 的 loop head（被 goto 指向最多的 label）
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
            boolean changed = insertNoiseBeforeIfs(orig, out, trapRange, anchor);
            if (changed) injectHead(out, head);
            return changed;
        }

        // 收集块出口：ASSIGN state = "key" 紧跟 GOTO loopHead
        List<Integer> exitPos = new ArrayList<>();
        List<String> keys = new ArrayList<>();
        for (int i = 0; i + 1 < orig.size(); i++) {
            Stmt a = orig.get(i), b = orig.get(i + 1);
            if (a.st == Stmt.ST.ASSIGN && b.st == Stmt.ST.GOTO
                    && ((GotoStmt) b).target == loopHead) {
                Value v = ((Stmt.E2Stmt) a).getOp2();
                if (v.vt == Value.VT.CONSTANT && ((Constant) v).value instanceof String) {
                    keys.add((String) ((Constant) v).value);
                    if (!trapRange.contains(i)) exitPos.add(i);
                }
            }
        }
        if (exitPos.size() < 2) {
            boolean changed = insertNoiseBeforeIfs(orig, out, trapRange, anchor);
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

            // 收集所有非 realKey 的候选，供各层假目标分别挑选
            List<String> others = new ArrayList<>();
            for (String k : keys) {
                if (!k.equals(realKey)) others.add(k);
            }
            if (others.isEmpty()) { out.add(orig.get(i)); continue; }

            emitGatedAssignment(out, target, realKey, others, anchor);
        }
        injectHead(out, head);
        return true;
    }

    /**
     * 发射带不透明门控的赋值。
     *
     * 每个块随机决定：层数（1..maxLayers）、每层用哪种恒真式、
     * 每层的假目标（从 others 里独立随机选）。
     *
     * 结构（3 层为例）：
     *
     *   if (!P_a) goto fake1        ← P_a 恒真，所以永远不跳
     *   if (!P_b) goto fake2
     *   if (!P_c) goto fake3
     *   state = realKey;            ← 真实路径
     *   goto join
     * fake1: state = X1; goto join
     * fake2: state = X2; goto join
     * fake3: state = X3; goto join
     * join:
     *
     * 注意各 fake 目标互不相同：攻击者不能靠「所有假边指向同一块」筛掉。
     */
    private void emitGatedAssignment(List<Stmt> out, Local target, String realKey,
                                     List<String> others, Local anchor) {
        int n = 1 + random.nextInt(maxLayers);
        // 每层独立选谓词种类，且相邻层不重复（避免固定序列）
        int[] kinds = new int[n];
        int prev = -1;
        for (int i = 0; i < n; i++) {
            int k;
            do {
                k = random.nextInt(IdentityBuilder.SIZE);
            } while (k == prev && IdentityBuilder.SIZE > 1);
            kinds[i] = k;
            prev = k;
        }

        List<LabelStmt> fakeLabels = new ArrayList<>();
        for (int i = 0; i < n; i++) fakeLabels.add(newLabel());
        LabelStmt join = newLabel();

        // 门控：if (!P) goto fake_i
        for (int i = 0; i < n; i++) {
            int salt = random.nextInt();
            Value cond = IdentityBuilder.build(kinds[i], anchor, salt, false); // 恒假
            out.add(Stmts.nIf(cond, fakeLabels.get(i)));
        }
        out.add(Stmts.nAssign(target, stringConst(realKey)));
        out.add(Stmts.nGoto(join));

        // 各假分支：独立挑假目标
        for (int i = 0; i < n; i++) {
            out.add(fakeLabels.get(i));
            String fake = others.get(random.nextInt(others.size()));
            out.add(Stmts.nAssign(target, stringConst(fake)));
            out.add(Stmts.nGoto(join));
        }
        out.add(join);
    }

    /** 无平坦化结构时的退化处理：在每个可插入的 IF 前加一条恒假门控。 */
    private boolean insertNoiseBeforeIfs(List<Stmt> orig, List<Stmt> out,
                                         Set<Integer> trapRange, Local anchor) {
        int n = 0;
        for (int idx = 0; idx < orig.size(); idx++) {
            Stmt st = orig.get(idx);
            if (st.st == Stmt.ST.IF && !trapRange.contains(idx) && random.nextBoolean()) {
                LabelStmt skip = newLabel();
                int kind = random.nextInt(IdentityBuilder.SIZE);
                Value cond = IdentityBuilder.build(kind, anchor, random.nextInt(), false);
                out.add(Stmts.nIf(cond, skip));
                out.add(skip);
                n++;
            }
            out.add(st);
        }
        return n > 0;
    }

    private void injectHead(List<Stmt> out, List<Stmt> head) {
        if (head.isEmpty()) return;
        List<Stmt> merged = new ArrayList<>(out.size() + head.size());
        merged.addAll(head);
        merged.addAll(out);
        out.clear();
        out.addAll(merged);
    }

    /**
     * 选 anchor：进入循环前【必然已初始化】、且攻击者无法静态定值的 int。
     *
     * 优先级：
     *   ① int 参数 —— JVM 保证入口已初始化，值来自调用方
     *   ② 方法内已有 int 局部 —— 必须确认它在 loop head 之前被赋值，
     *      否则未初始化 slot 在类型合并时退化为 UNINITIALIZED_VALUE，
     *      dx 会报 local XXXX: invalid。这里保守地不用它。
     *   ③ 新造 slot，用运行时派生值初始化：
     *        System.nanoTime() >>> 3 ^ availableProcessors()
     *      nanoTime 每次调用都不同，攻击者无法认为它是已知常量；
     *      而三条恒真式对【任意】int 都成立，所以取什么值都不影响语义。
     */
    private Local pickAnchor(IrMethod ir, List<Stmt> head) {
        int slot = ir.isStatic ? 0 : 1;
        if (ir.args != null) {
            for (String t : ir.args) {
                if ("I".equals(t)) {
                    for (Local l : ir.locals) {
                        if (l._ls_index == slot && "I".equals(l.valueType)) {
                            return l;
                        }
                    }
                }
                slot += ("J".equals(t) || "D".equals(t)) ? 2 : 1;
            }
        }
        Local fresh = newLocal(ir, "op_anchor", "I");
        head.add(Stmts.nAssign(fresh, runtimeNoise()));
        return fresh;
    }

    /** System.nanoTime() 派生值：每次都不同，静态无从定值。 */
    private Value runtimeNoise() {
        Value nano = IdentityBuilder.invokeStatic("Ljava/lang/System;",
                "nanoTime", new String[]{}, "J");
        // nanoTime 返回 long，取高位再和 CPU 数异或，压成 int
        Value hi = IdentityBuilder.bin(VT.USHR, nano, IdentityBuilder.i32(32), "J");
        // ⚠️ CastExpr 同样要把类型写进 valueType，
        //    否则 IR2JConverter.getOpcode(v.valueType.charAt(0)) NPE
        CastExpr cast = Exprs.nCast(hi, "J", "I");
        cast.valueType = "I";
        Value asInt = cast;
        InvokeExpr runtime = IdentityBuilder.invokeStatic("Ljava/lang/Runtime;",
                "getRuntime", new String[]{}, "Ljava/lang/Runtime;");
        Value cpu = IdentityBuilder.invokeVirtual(new Value[]{runtime},
                "Ljava/lang/Runtime;", "availableProcessors", new String[]{}, "I");
        return IdentityBuilder.bin(VT.XOR, asInt, cpu, "I");
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

    private Constant stringConst(String s) {
        Constant c = Exprs.nString(s);
        c.valueType = "Ljava/lang/String;";
        return c;
    }

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
