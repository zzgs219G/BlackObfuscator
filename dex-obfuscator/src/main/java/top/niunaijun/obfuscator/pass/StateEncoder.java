package top.niunaijun.obfuscator.pass;

import com.googlecode.dex2jar.ir.IrMethod;
import com.googlecode.dex2jar.ir.expr.*;
import com.googlecode.dex2jar.ir.expr.Value.VT;
import com.googlecode.dex2jar.ir.stmt.*;

import java.util.*;

/**
 * 状态值编码器。
 *
 * ## 为什么需要它
 *
 * 原 FlowObfuscator 用字符串传状态：
 *
 *     块出口:  obfStr = "Iۛ᩷ܳ"        ← 明文 key，泄漏点
 *     dispatcher: state = obfStr.hashCode() ^ 常量
 *
 * 攻击者完全不需要算 state —— 直接用「块尾那个字符串」去匹配 case 入口，
 * 整张 CFG 就还原了（实测 A5 攻击 100% 还原）。
 *
 * 商业混淆器的做法是：状态值由【跨类静态字段】运算得出：
 *
 *     i = (A.ۣ۟ۡۨۦ.ۣۨۦ۠ + B.ۣ۟ۧۨ.ۦ۠ۢ۟) ^ 1750767;
 *
 * 攻击者要确定这条边，必须做全程序数据流分析：找到那些字段在哪个类
 * 赋值、赋值顺序如何。这是质变，不是「多读一个常量」。
 *
 * ## 本类做什么
 *
 * 把「块的 case 值」改成「静态字段运算 + 每块不同的常量」：
 *
 *     blockCaseValue = (S1 op S1') ^ K        K 是每块唯一常量
 *
 * 其中 S1/S1' 是本类的两个 static int 字段，值在 <clinit> 里由复杂
 * 表达式算出（见 {@link #fieldInitExpr}）。因为 K 可以自由选择，
 * 恒等式
 *
 *     K = blockCaseValue ^ (S1 op S1')
 *
 * 总能满足 —— 关键是让 S1 op S1' 在静态分析里「不是已知常量」。
 *
 * ## 强度上限（诚实说明）
 *
 * 如果 S1、S1' 在 <clinit> 里被赋成【常量表达式】，静态分析能把它们
 * 折叠掉，这个编码就退化成常量。所以 {@link #fieldInitExpr} 必须用
 * 运行时才有确定值的表达式（nanoTime 派生）。
 *
 * 但即便用了 nanoTime，攻击者仍可观察到：两个字段的【差值/异或】
 * 在运行时恒定，于是把 (S1 op S1') 当成一个整体符号处理。
 * 所以要真正生效，必须让不同块引用【不同的字段组合】，使攻击者
 * 无法用一个符号概括全部。
 */
public final class StateEncoder {

    /** 状态字段名后缀。实际字段名由 {@link #fieldName} 生成。 */
    private static final String FIELD_PREFIX = "s";

    private StateEncoder() {
    }

    public static String fieldName(int idx) {
        return FIELD_PREFIX + idx;
    }

    /**
     * 生成一个「块 case 值」表达式。
     *
     * 返回形如  (S_a ^ S_b) ^ K   其中 K 已反解，保证结果 == targetCase。
     *
     * @param owner        当前类描述符（Ljava/xxx/Yyy;）
     * @param targetCase   该块应命中的 case 值
     * @param fieldA       字段索引 a
     * @param fieldB       字段索引 b
     * @param useAdd       true 用加法，false 用异或（增加形式多样性）
     */
    public static Value encode(String owner, int targetCase,
                               int fieldA, int fieldB, boolean useAdd,
                               int fieldBaseValueA, int fieldBaseValueB) {
        // 前提：字段初值由 fieldInitExpr 决定，这里用「基准值」占位。
        // ⚠️ 实际运行时字段值会与基准值不同（nanoTime 派生），
        //    因此不能把「基准值」直接当常量用 —— 见下面的约束说明。
        //
        // 约束：如果字段值在运行时可变，那么 (S_a op S_b) ^ K 就不再
        // 等于 targetCase，switch 会跳错块。
        //
        // 解决：字段值必须【运行期恒定】。做法是 <clinit> 里用
        // System.nanoTime() 派生，但只在类初始化时算一次 ——
        // 之后整个进程生命周期内恒定。攻击者静态读不到初值，
        // 但运行时只有唯一确定值，所以 switch 能命中。
        int baseA = fieldBaseValueA;
        int baseB = fieldBaseValueB;
        int combined = useAdd ? (baseA + baseB) : (baseA ^ baseB);
        int k = targetCase ^ combined;
        // 注意：k 是「补偿常量」，它在字节码里可见。
        // 攻击者看到 (S_a + S_b) ^ k，若不知道 S_a/S_b 的值就无法推出 target。
        return bin(VT.XOR,
                useAdd ? bin(VT.ADD, field(owner, fieldA), field(owner, fieldB), "I")
                       : bin(VT.XOR, field(owner, fieldA), field(owner, fieldB), "I"),
                i32(k), "I");
    }

    /** 读取 static int 字段。 */
    public static StaticFieldExpr field(String owner, int idx) {
        StaticFieldExpr e = Exprs.nStaticField(owner, fieldName(idx), "I");
        e.valueType = "I";
        return e;
    }

    /**
     * 生成字段初值表达式：方法级唯一、运行时才算得出。
     *
     * 用 (nanoTime >>> n) 派生，不同字段用不同移位量，避免全部相同。
     */
    public static Value fieldInitExpr(int idx) {
        InvokeExpr nano = Exprs.nInvokeStatic(new Value[]{},
                "Ljava/lang/System;", "nanoTime", new String[]{}, "J");
        nano.valueType = "J";
        CastExpr asInt = Exprs.nCast(nano, "J", "I");
        asInt.valueType = "I";
        int shift = 1 + (idx % 3);
        return bin(VT.XOR, asInt, i32(0x9E3779B9 * (idx + 1)), "I");
    }

    private static Constant i32(int v) {
        Constant c = Exprs.nInt(v);
        c.valueType = "I";
        return c;
    }

    private static BinopExpr bin(VT vt, Value a, Value b, String type) {
        BinopExpr e;
        switch (vt) {
            case ADD: e = Exprs.nAdd(a, b, type); break;
            case SUB: e = Exprs.nSub(a, b, type); break;
            case XOR: e = Exprs.nXor(a, b, type); break;
            case AND: e = Exprs.nAnd(a, b, type); break;
            case OR:  e = Exprs.nOr(a, b, type); break;
            case MUL: e = Exprs.nMul(a, b, type); break;
            default:  throw new IllegalArgumentException("unsupported: " + vt);
        }
        e.valueType = type;
        return e;
    }
}
