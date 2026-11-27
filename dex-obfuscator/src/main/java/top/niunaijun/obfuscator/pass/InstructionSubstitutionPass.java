package top.niunaijun.obfuscator.pass;

import com.googlecode.dex2jar.ir.IrMethod;
import com.googlecode.dex2jar.ir.expr.*;
import com.googlecode.dex2jar.ir.stmt.*;
import top.niunaijun.obfuscator.ObfuscationPass;
import top.niunaijun.obfuscator.chain.base.BaseObfuscatorChain;

import java.util.List;
import java.util.Random;

/**
 * 模块：指令替换（Instruction Substitution）。
 *
 * 把简单运算换成等价但更啰嗦的形式，消掉常量折叠和模式匹配的空间：
 *
 *     a + b   →  (a ^ r) + (b ^ r) ^ (r + r)   的常用简化版：
 *                a + b  →  a - (-b)
 *     a - b   →  a + (-b)
 *     a ^ c   →  (a ^ r) ^ (c ^ r)
 *
 * 与旧 SubObfuscator 的区别：
 *   · 旧版硬编码在 chain 里，无法关闭、无法独立验证
 *   · 本 Pass 可单独开关，且只处理 IR 中确实存在的 BinopExpr
 *
 * 强度说明（诚实）：单纯指令替换对**愿意看汇编的人**几乎无效，
 * jadx / dex2jar 的简单折叠就能消掉大部分。它的价值在于
 * 增加「模式匹配」类自动化工具的成本，不是决定性防护。
 * 真正的强度来自 OpaquePredicatePass 和 FlowObfuscator。
 */
public class InstructionSubstitutionPass implements ObfuscationPass {

    private final Random random = new Random();
    private final int depth;

    public InstructionSubstitutionPass(int depth) {
        this.depth = Math.max(1, depth);
    }

    @Override
    public String name() {
        return "instruction-substitution";
    }

    @Override
    public boolean accept(IrMethodInfo ir) {
        return ir.trapCount() == 0;
    }

    @Override
    public boolean apply(IrMethodInfo info, List<Stmt> orig, List<Stmt> out) {
        IrMethod ir = info.raw();
        boolean changed = false;

        for (Stmt st : orig) {
            if ((st.st == Stmt.ST.ASSIGN || st.st == Stmt.ST.IDENTITY)
                    && st instanceof Stmt.E2Stmt) {
                Stmt.E2Stmt e2 = (Stmt.E2Stmt) st;
                Value v2 = e2.getOp2();
                Value replaced = substitute(v2, ir);
                if (replaced != null) {
                    e2.op2 = replaced;
                    changed = true;
                }
            }
            out.add(st);
        }
        return changed;
    }

    /** 返回替换后的表达式；返回 null 表示不改。 */
    private Value substitute(Value v, IrMethod ir) {
        if (v == null) return null;
        switch (v.vt) {
            case ADD: {
                // a + b  →  a - (-b)
                if (random.nextBoolean()) {
                    BinopExpr b = (BinopExpr) v;
                    return Exprs.nSub(b.getOp1(), negOf(b.getOp2()), b.valueType);
                }
                return null;
            }
            case SUB: {
                // a - c  →  a + (-c)
                BinopExpr b = (BinopExpr) v;
                return Exprs.nAdd(b.getOp1(), negOf(b.getOp2()), b.valueType);
            }
            case XOR: {
                // a ^ c  →  (a ^ r) ^ (c ^ r)，r 为随机常量
                BinopExpr b = (BinopExpr) v;
                if (!"I".equals(b.valueType)) return null;
                Constant r = Exprs.nInt(random.nextInt());
                r.valueType = "I";
                Constant c = asIntConstant(b.getOp2());
                if (c == null) return null;
                Constant cXorR = Exprs.nInt(((Integer) c.value) ^ ((Integer) r.value));
                cXorR.valueType = "I";
                Constant r2 = Exprs.nInt((Integer) r.value);
                r2.valueType = "I";
                return Exprs.nXor(Exprs.nXor(b.getOp1(), r2, "I"), cXorR, "I");
            }
            default:
                return null;
        }
    }

    /**
     * 构造 -v。
     *
     * ⚠️ UnopExpr 把类型存在 `type` 字段，而 IR2JConverter 取的是 `valueType`：
     *     IR2JConverter.getOpcode(Value v) -> v.valueType.charAt(0)
     * 只设 type 会让 valueType 保持 null，转换时直接 NPE。
     * 两处都要设。
     */
    private UnopExpr negOf(Value v) {
        String t = intTypeOf(v);
        UnopExpr neg = Exprs.nNeg(v, t);
        neg.valueType = t;
        return neg;
    }

    private Constant asIntConstant(Value v) {
        if (v.vt != Value.VT.CONSTANT) return null;
        Constant c = (Constant) v;
        return (c.value instanceof Integer) ? c : null;
    }

    private String intTypeOf(Value v) {
        String t = v.valueType;
        return (t == null || t.isEmpty()) ? "I" : t;
    }
}
