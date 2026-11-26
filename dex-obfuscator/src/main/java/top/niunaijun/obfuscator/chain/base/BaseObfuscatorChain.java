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
        // 换了方法就重置 key 去重池：同一方法内 key 必须互异（见 randomString 说明），
        // 跨方法复用则无害 —— obfIndexI 不同，switchBlock 也是方法局部的。
        if (irMethod != ir) {
            irMethod = ir;
            usedKeyHashes.clear();
        }
        localIndex = ir.locals.size() * 2;
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

    /**
     * 生成本次混淆使用的 key 序列。
     *
     * ⚠️ 2026-11-27 重写：改用 ObfDic 的 40494 条字典（`I` + 34 个神秘字符的排列）。
     *
     * 与旧实现的两点区别：
     *   ① 长度：旧实现拼 10~18 个「字」、每字 3~4 字符，单 key 平均 44.5 字符；
     *      现在直接取表，长度固定为 2~4 字符（前缀 + 1~3 个后缀字符）。
     *   ② 唯一性：这是必须的。调用方会用 key 构造
     *          Map&lt;Integer, LabelStmt&gt; switchBlock
     *      由 `key.hashCode() ^ obfIndexI` 作索引。一旦两个块拿到相同 key，
     *      Map 会覆盖掉前一个 → 该块在 dispatcher 里没有 case 可达 →
     *      运行时走 default 死循环，或产出非法字节码。
     *      旧实现靠「长度足够长」把碰撞概率压到极低，现在字典只有 40494 条，
     *      单个方法几十个块时 Birthday 碰撞概率不可忽略，因此显式去重。
     *
     * 注意：去重只保证【同一方法内】不重复，跨方法复用不影响正确性
     * （每个方法的 obfIndexI 不同，且 switchBlock 是方法局部的）。
     */
    private final java.util.Set<Integer> usedKeyHashes = new java.util.HashSet<>();

    public String randomString(int depth) {
        java.util.Random random = new java.util.Random();
        // 去重必须按 hashCode 而不是字符串本身：
        // 字典 40494 条里 hashCode 只有 31708 个不同值（78.3%），
        // 若按字符串去重，仍会出现两个不同 key 映射到同一 case 值的情况，
        // Map<Integer, LabelStmt> switchBlock 会被覆盖 → 块丢失。
        for (int attempt = 0; attempt < ObfDic.SIZE * 2; attempt++) {
            String key = ObfDic.at(random.nextInt(ObfDic.SIZE));
            if (usedKeyHashes.add(key.hashCode())) {
                return key;
            }
        }
        return ObfDic.at(random.nextInt(ObfDic.SIZE));
    }

    /** 每次开始处理一个新方法前调用，重置去重集合。 */
    public void resetKeyPool() {
        usedKeyHashes.clear();
    }
}
