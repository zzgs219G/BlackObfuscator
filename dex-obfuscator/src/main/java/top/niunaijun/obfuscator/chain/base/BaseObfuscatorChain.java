package top.niunaijun.obfuscator.chain.base;

import com.googlecode.dex2jar.ir.IrMethod;
import com.googlecode.dex2jar.ir.expr.Exprs;
import com.googlecode.dex2jar.ir.expr.Local;
import com.googlecode.dex2jar.ir.stmt.Stmt;
import top.niunaijun.obfuscator.ObfDic;
import top.niunaijun.obfuscator.ObfuscatorConfiguration;
import top.niunaijun.obfuscator.RebuildIfResult;

import java.util.List;
import java.util.Random;

public abstract class BaseObfuscatorChain implements ObfuscatorChain {

    private int localIndex;
    private IrMethod irMethod;
    protected int depth;
    protected ObfuscatorConfiguration obfuscatorConfiguration;

    public BaseObfuscatorChain(ObfuscatorConfiguration obfuscatorConfiguration) {
        this.obfuscatorConfiguration = obfuscatorConfiguration;
        this.depth = obfuscatorConfiguration.getObfDepth();
    }

    @Override
    public boolean canDepth() {
        return true;
    }

    public abstract RebuildIfResult reBuild0(IrMethod ir, Stmt stmt, List<Stmt> origStmts);

    @Override
    public final RebuildIfResult reBuild(IrMethod ir, Stmt stmt, List<Stmt> origStmts) {
        localIndex = ir.locals.size() * 2;
        irMethod = ir;
        return reBuild0(ir, stmt, origStmts);
    }

    /**
     * 新建一个 Local，并分配一个与现有槽位不冲突的寄存器编号。
     *
     * ⚠️ 2026-11-27 修（两处）：
     *   ① 原实现 `Exprs.nLocal(++localIndex, name)` 里 localIndex 是实例字段、
     *      在 reBuild 时重置为 `ir.locals.size() * 2`。但 `locals.size()` ≠ 最大
     *      _ls_index，且 Flow/Sub/If 三个 chain 各持一个实例、各自重置 →
     *      不同 Local 拿到相同编号。
     *   ② 更隐蔽的一处：J/D（long/double）在 JVM 里占 **2 个槽位**。
     *      只按「max + 1」分配会让一个新 int 恰好落在某个 long 的第二个槽位上，
     *      直接把那个 long 拆坏：
     *        LLOAD 8 / PUTFIELD ...E:J  ← slot 8 被 int 覆写
     *        verifier: Expected J, but found .
     *   现在按「所有 Local 的 _ls_index + 类型宽度」求上界，宽度为 J/D 时占 2 格。
     *   dex2jar 自己的 Ir2JRegAssignTransformer 也是按宽度着色（见其
     *   `excludeColor.get(i) && excludeColor.get(i + 1)`），这里保持一致。
     */
    public Local newLocal(String name, String type) {
        Local local = Exprs.nLocal(nextFreeSlot(), name);
        local.valueType = type;
        irMethod.locals.add(local);
        localIndex = local._ls_index;
        return local;
    }

    /**
     * 当前 method 里第一个可用的局部变量槽位。
     * 负编号（dex2jar 用 -1 / -2 表示「已丢弃 / 不要分配」）不占槽。
     */
    public int nextFreeSlot() {
        int next = 0;
        for (Local l : irMethod.locals) {
            if (l._ls_index < 0) {
                continue;
            }
            int end = l._ls_index + slotWidth(l.valueType);
            if (end > next) {
                next = end;
            }
        }
        return next;
    }

    /** JVM 局部变量槽位数：long / double 占 2，其余占 1。 */
    public static int slotWidth(String type) {
        if (type == null || type.length() == 0) {
            return 1;
        }
        char c = type.charAt(0);
        return (c == 'J' || c == 'D') ? 2 : 1;
    }

//    int index = 0;
//    public String randomString(int depth) {
//        return (index++) + "";
//    }

    public String randomString(int depth) {
        int length = (new Random().nextInt(5 ) + 5) * depth;
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < length; i++) {
            stringBuilder.append(ObfDic.dic[new Random().nextInt(ObfDic.dic.length - 1)]);
        }
        return stringBuilder.toString();
    }
}
