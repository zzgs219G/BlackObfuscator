package top.niunaijun.obfuscator;

public abstract class ObfuscatorConfiguration {

	/**
	 * 混淆深度
	 */
	public int getObfDepth() {
		return 1;
	}

	/**
	 * 是否处理此method
	 * @param className className
	 * @param methodName methodName
	 */
	public boolean accept(String className, String methodName) {
		return true;
	}

	/**
	 * 不透明谓词的嵌套层数（1~3）。
	 *
	 * 与 {@link #getObfDepth()} 分开，是因为两者含义不同：
	 *   getObfDepth()   —— chain 的重复次数（Flow/If/Sub 各自只跑一次，实际影响很小）
	 *   getOpaqueLayers() —— 谓词的嵌套深度，直接决定抗静态分析强度
	 * 之前共用一个参数，调深度会意外改变谓词强度，不好控制。
	 */
	public int getOpaqueLayers() {
		return 2;
	}

	/**
	 * 启用哪些混淆模块。
	 *
	 * 返回 null 表示全部启用（默认行为，兼容旧调用）。
	 * 返回集合时，只有集合里的模块生效。
	 *
	 * 可用模块名见 {@link top.niunaijun.obfuscator.pass.PassRegistry}：
	 *   flow / if / sub / instruction-substitution / opaque-predicate
	 */
	public java.util.Set<String> getEnabledModules() {
		return null;
	}
}
