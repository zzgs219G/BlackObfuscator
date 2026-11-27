package top.niunaijun.obfuscator.pass;

import com.googlecode.dex2jar.ir.expr.*;
import com.googlecode.dex2jar.ir.expr.Value.VT;

/**
 * 数论恒真式的 IR 构造器。
 *
 * 每条式子对【任意 int x】恒真（含 Java 溢出语义）。
 * 记 x 为 anchor，来自方法参数或运行时派生值，静态不可定值。
 *
 * | # | 恒真形式                        | 恒假形式（取反）      | 依据                      |
 * |---|--------------------------------|----------------------|---------------------------|
 * | 0 | (x * (x+1)) % 2 == 0           | != 0                 | 连续两整数必有一偶         |
 * | 1 | (x \| 1) != 0                   | == 0                 | x\|1 为奇数                |
 * | 2 | (x ^ (x >> 31)) >= 0           | < 0                  | 符号位被异或消掉           |
 * | 3 | (x ^ x) == 0                   | != 0                 | 自反                       |
 * | 4 | (x - x) == 0                   | != 0                 | 自反                       |
 * | 5 | ((x & 1) * 2) % 2 == 0         | != 0                 | 任何整数乘 2 必偶          |
 * | 6 | (x % 2) * (x % 2) <= 1         | > 1                  | mod 2 只取 0/1             |
 * | 7 | (x & 0) == 0                   | != 0                 | 与零                    |
 * | 8 | ((x >> 1) << 1) != (x \| 1)     | ==                   | bit0 清掉后不可能等于置 1  |
 * | 9 | (x ^ (x ^ -1)) == -1           | != -1                | 三重异或消元               |
 * | 10| (x \| (x ^ -1)) == -1           | != -1                | x 与 !x 并集为全 1         |
 * | 11| (x * 0) == 0                   | != 0                 | 乘零                       |
 *
 * 3/4/7/11 能被常量折叠直接算出来，但它们混在池子里，攻击者不能
 * 假定所有块都用弱式子 —— 判断成本按最坏情况算。
 * 0/1/2/5/6/8/9/10 需要真正的数学性质，静态分析必须上位向量求解。
 *
 * ## 取反为什么在比较符层面做
 *
 * 不能用 `(恒真式) == 0` 这种写法：dex2jar 的 EQ/NE/LT 等是【条件跳转
 * 用的布尔语义】，当 int 值再用会栈深度错乱（实测 mismatched stack depths）。
 * 所以每种形式都直接给出恒真 / 恒假两个比较符。
 */
public class IdentityBuilder {

    /** 恒真式种类数。 */
    public static final int SIZE = 12;

    /**
     * 构造恒真（wantTrue=true）或恒假（wantTrue=false）的条件。
     *
     * @param kind   形式编号 0..SIZE-1
     * @param x      anchor，任意 int
     * @param salt   随机盐，用于让同种形式在不同块也略有差异
     * @param wantTrue true 求恒真式，false 求恒假式
     */
    public static Value build(int kind, Value x, int salt, boolean wantTrue) {
        int k = salt | 1;   // 奇数，非零
        switch (kind) {
            case 0:
                // (x * (x+1)) % 2  OP 0
                return bin(wantTrue ? VT.EQ : VT.NE,
                        bin(VT.REM, bin(VT.MUL, x, bin(VT.ADD, x, i32(1), "I"), "I"),
                                i32(2), "I"),
                        i32(0), "I");

            case 1:
                // (x | 1)  OP 0
                return bin(wantTrue ? VT.NE : VT.EQ,
                        bin(VT.OR, x, i32(1), "I"), i32(0), "I");

            case 2:
                // (x ^ (x >> 31))  OP 0
                return bin(wantTrue ? VT.GE : VT.LT,
                        bin(VT.XOR, x, bin(VT.SHR, x, i32(31), "I"), "I"),
                        i32(0), "I");

            case 3:
                // (x ^ x)  OP 0
                return bin(wantTrue ? VT.EQ : VT.NE,
                        bin(VT.XOR, x, x, "I"), i32(0), "I");

            case 4:
                // (x - x)  OP 0
                return bin(wantTrue ? VT.EQ : VT.NE,
                        bin(VT.SUB, x, x, "I"), i32(0), "I");

            case 5:
                // ((x & 1) * 2) % 2  OP 0 —— 乘 2 后必偶
                return bin(wantTrue ? VT.EQ : VT.NE,
                        bin(VT.REM,
                                bin(VT.MUL, bin(VT.AND, x, i32(1), "I"), i32(2), "I"),
                                i32(2), "I"),
                        i32(0), "I");

            case 6:
                // (x % 2) * (x % 2)  OP 1
                return bin(wantTrue ? VT.LE : VT.GT,
                        bin(VT.MUL, bin(VT.REM, x, i32(2), "I"),
                                bin(VT.REM, x, i32(2), "I"), "I"),
                        i32(1), "I");

            case 7:
                // (x & 0)  OP 0
                return bin(wantTrue ? VT.EQ : VT.NE,
                        bin(VT.AND, x, i32(0), "I"), i32(0), "I");

            case 8:
                // ((x >> 1) << 1)  OP  (x | 1)
                return bin(wantTrue ? VT.NE : VT.EQ,
                        bin(VT.SHL, bin(VT.SHR, x, i32(1), "I"), i32(1), "I"),
                        bin(VT.OR, x, i32(1), "I"), "I");

            case 9:
                // (x ^ (x ^ -1))  OP -1
                return bin(wantTrue ? VT.EQ : VT.NE,
                        bin(VT.XOR, x, bin(VT.XOR, x, i32(-1), "I"), "I"),
                        i32(-1), "I");

            case 10:
                // (x | (x ^ -1))  OP -1
                return bin(wantTrue ? VT.EQ : VT.NE,
                        bin(VT.OR, x, bin(VT.XOR, x, i32(-1), "I"), "I"),
                        i32(-1), "I");

            default:
                // (x * 0)  OP 0
                return bin(wantTrue ? VT.EQ : VT.NE,
                        bin(VT.MUL, x, i32(0), "I"), i32(0), "I");
        }
    }

    /**
     * 构造静态调用并把返回类型写进 valueType。
     *
     * ⚠️ InvokeExpr 把返回类型存在 method.getReturnType()，而 IR2JConverter
     * 用的是 `value.valueType`（见 reBuildE2Expression 的 tp1）。只靠构造器
     * 不设 valueType 会在二元运算里 NPE。
     */
    public static InvokeExpr invokeStatic(String owner, String name,
                                          String[] argTypes, String retType) {
        InvokeExpr e = Exprs.nInvokeStatic(new Value[]{}, owner, name, argTypes, retType);
        e.valueType = retType;
        return e;
    }

    /** 构造虚调用并把返回类型写进 valueType。 */
    public static InvokeExpr invokeVirtual(Value[] args, String owner, String name,
                                           String[] argTypes, String retType) {
        InvokeExpr e = Exprs.nInvokeVirtual(args, owner, name, argTypes, retType);
        e.valueType = retType;
        return e;
    }

    static Constant i32(int v) {
        Constant c = Exprs.nInt(v);
        c.valueType = "I";
        return c;
    }

    static BinopExpr bin(VT vt, Value a, Value b, String type) {
        BinopExpr e;
        switch (vt) {
            case GT:   e = Exprs.nGt(a, b, type); break;
            case LT:   e = Exprs.nLt(a, b, type); break;
            case GE:   e = Exprs.nGe(a, b, type); break;
            case LE:   e = Exprs.nLe(a, b, type); break;
            case EQ:   e = Exprs.nEq(a, b, type); break;
            case NE:   e = Exprs.nNe(a, b, type); break;
            case MUL:  e = Exprs.nMul(a, b, type); break;
            case REM:  e = Exprs.nRem(a, b, type); break;
            case ADD:  e = Exprs.nAdd(a, b, type); break;
            case SUB:  e = Exprs.nSub(a, b, type); break;
            case OR:   e = Exprs.nOr(a, b, type); break;
            case AND:  e = Exprs.nAnd(a, b, type); break;
            case XOR:  e = Exprs.nXor(a, b, type); break;
            case SHR:  e = Exprs.nShr(a, b, type); break;
            case SHL:  e = Exprs.nShl(a, b, type); break;
            case USHR: e = Exprs.nUshr(a, b, type); break;
            default:   throw new IllegalArgumentException("unsupported: " + vt);
        }
        e.valueType = type;
        return e;
    }
}
