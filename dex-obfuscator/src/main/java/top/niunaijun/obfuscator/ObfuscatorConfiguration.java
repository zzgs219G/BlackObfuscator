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
