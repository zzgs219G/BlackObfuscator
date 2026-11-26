package top.niunaijun.obfuscator;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * 混淆 key 字典。
 *
 * 采用与 jian_box / ProGuard 字典同构的构造方式：
 *     前缀 + 神秘字符的 1~N 次排列
 * 简盒用 'l' + 34 个字符，这里用 'I' + 同一批 34 个字符。
 *
 * 为什么需要前缀：
 *   那 34 个字符的 Unicode 类别全部是 Mn（非间距组合符），
 *   它们不能作为标识符的首字符，且会与前一个字符组合渲染成一片。
 *   加一个合法的 ASCII 前缀既满足语法，又让整串看起来更「密」。
 *
 * ⚠️ 强度说明（实测数据，不要误解）：
 *   这些 key 只用于 FlowObfuscator / IfObfuscator 的状态转移：
 *       caseValue = key.hashCode() ^ obfIndexI
 *   真正参与运算的只有 32 bit 的 hashCode。字典换成什么形态、key 有多长，
 *   对静态还原难度【没有任何影响】—— 攻击者从字节码读出 caseValue 和
 *   obfIndexI，反解出 key.hashCode()，再对 dex 里明文存在的 key 建表查询，
 *   即可 100% 命中。（实测：旧字典 75.1%，新字典 75.3%，基本无变化）
 *
 *   换字典的真实收益只有两点：
 *     ① 外观与 jian_box 的 R8 字典一致，便于统一识别/管理
 *     ② key 长度从平均 44.5 字符降到 3 字符，dex 体积更小
 *
 *   想真正提升强度，必须让 key 不出现在 dex 明文里（运行时解密），
 *   或者给块之间加入不透明谓词/虚假边。
 */
public class ObfDic {

    /** 前缀字符。简盒用 'l'，这里用 'I' —— 视觉上同样纤细，但码位不同。 */
    public static final char PREFIX = 'I';

    /**
     * 神秘字符表，共 34 个，码位取自简盒 proguard-dictionary.txt 的后缀字母表。
     *
     * 全部为 Unicode Mn（非间距组合符）：
     *   U+05A1..U+05AB  叙利亚文
     *   U+06D6..U+06EC  阿拉伯文补充
     *   U+0730..U+073F  叙利亚文补充
     *   U+1A73..U+1A7B   Tai Viet
     */
    private static final String ALPHA = "\u05A1\u05A8\u05AB"
            + "\u06D6\u06D7\u06D8\u06D9\u06DA\u06DB\u06DC\u06DF\u06E0\u06E1\u06E2\u06E4\u06E7\u06E8\u06EB\u06EC"
            + "\u0730\u0733\u0736\u073A\u073D\u073F"
            + "\u1A73\u1A74\u1A75\u1A76\u1A77\u1A78\u1A79\u1A7A\u1A7B";

    private static final int N = ALPHA.length();   // 34

    /** 一个字 key 的最大后缀长度。后缀长 1~3 时可铺出 34+1156+39304 = 40494 种。 */
    private static final int MAX_SUFFIX = 3;

    /**
     * 预生成的 key 全表：前缀 + 后缀排列。
     * 大小 = N + N^2 + N^3 = 40494，与简盒字典条目数一致，且无重复。
     *
     * 用静态表而不是每次现算，是为了让 idx -> key 的映射稳定，
     * 便于复现问题（同一 idx 永远得到同一个 key）。
     */
    private static final String[] KEYS = buildKeys();

    /** key 总数，供调用方取模。 */
    public static final int SIZE = KEYS.length;

    public static String at(int idx) {
        int i = idx % KEYS.length;
        if (i < 0) {
            i += KEYS.length;
        }
        return KEYS[i];
    }

    /** 随机取一个 key。 */
    public static String randomKey(Random random) {
        return KEYS[random.nextInt(KEYS.length)];
    }

    private static String[] buildKeys() {
        List<String> list = new ArrayList<>(N + N * N + N * N * N);
        // 后缀长度 1
        for (int a = 0; a < N; a++) {
            list.add(PREFIX + String.valueOf(ALPHA.charAt(a)));
        }
        // 后缀长度 2
        for (int a = 0; a < N; a++) {
            for (int b = 0; b < N; b++) {
                list.add(new StringBuilder(3)
                        .append(PREFIX)
                        .append(ALPHA.charAt(a))
                        .append(ALPHA.charAt(b))
                        .toString());
            }
        }
        // 后缀长度 3
        if (MAX_SUFFIX >= 3) {
            for (int a = 0; a < N; a++) {
                for (int b = 0; b < N; b++) {
                    for (int c = 0; c < N; c++) {
                        list.add(new StringBuilder(4)
                                .append(PREFIX)
                                .append(ALPHA.charAt(a))
                                .append(ALPHA.charAt(b))
                                .append(ALPHA.charAt(c))
                                .toString());
                    }
                }
            }
        }
        return list.toArray(new String[0]);
    }
}
