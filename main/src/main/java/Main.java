import com.googlecode.dex2jar.tools.BlackObfuscatorCmd;

/**
 * 命令行入口（2026-11-27 重写）。
 *
 * 原版硬编码了作者本机的 macOS 路径（/Users/milk/Documents/...），
 * 只能当示例看。现改为直接透传命令行参数。
 *
 * 用法：
 *   java -cp <classpath> Main -d 2 -i classes.dex -o out.dex -p com.example
 *
 * 参数见 BlackObfuscatorCmd 的 usage：
 *   -d  混淆深度
 *   -i  输入 dex
 *   -o  输出 dex
 *   -p  要混淆的包名（简单过滤）
 *   -a  允许清单文件路径
 */
public class Main {

    public static void main(String[] args) {
        // BlackObfuscatorCmd.main 的第一个参数是程序名，其后原样透传
        String[] full = new String[args.length + 1];
        full[0] = "d2j-black-obfuscator";
        System.arraycopy(args, 0, full, 1, args.length);
        BlackObfuscatorCmd.main(full);
    }
}
