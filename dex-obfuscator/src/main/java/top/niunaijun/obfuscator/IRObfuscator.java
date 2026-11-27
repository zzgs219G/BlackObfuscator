package top.niunaijun.obfuscator;

import com.googlecode.dex2jar.ir.IrMethod;
import com.googlecode.dex2jar.ir.stmt.*;
import top.niunaijun.obfuscator.chain.base.ObfuscatorChain;
import top.niunaijun.obfuscator.pass.PassRegistry;

import java.util.*;

public class IRObfuscator {

	private static IRObfuscator obfuscator;
	private final ObfuscatorConfiguration configuration;
	private final List<ObfuscatorChain> chains;
	private final PassRegistry registry;

	public static IRObfuscator get(ObfuscatorConfiguration obf) {
		if (obfuscator == null) {
			synchronized (IRObfuscator.class) {
				if (obfuscator == null) {
					obfuscator = new IRObfuscator(obf);
				}
			}
		}
		return obfuscator;
	}

	public IRObfuscator(ObfuscatorConfiguration configuration) {
		this.configuration = configuration;
		this.registry = new PassRegistry(configuration);
		this.chains = registry.chains();
	}

	public void reBuildInstructions(IrMethod ir) {
		if (configuration == null)
			return;
		if (!configuration.accept(ir.owner, ir.name)) {
			return;
		}

		// ---- 阶段一：逐语句 chain（Flow / If / Sub）----
		for (ObfuscatorChain chain : chains) {
			for (int i = 0; i < configuration.getObfDepth(); i++) {
				List<Stmt> newStmts = new ArrayList<>();
				List<Stmt> origStmts = new ArrayList<>();
				for (Stmt value : ir.stmts) {
					origStmts.add(value);
				}
				RebuildIfResult rebuildIfResult;
				for (Stmt stmt : ir.stmts) {
					if (chain.canHandle(ir, stmt)) {
						rebuildIfResult = chain.reBuild(ir, stmt, origStmts);
						if (rebuildIfResult != null) {
							newStmts.addAll(rebuildIfResult.getResult());
						}
					} else {
						newStmts.add(stmt);
					}
				}
				chain.reBuildEnd(ir, newStmts, origStmts);
				ir.stmts.clear();
				ir.stmts.addAll(newStmts);
				if (!chain.canDepth()) {
					break;
				}
			}
		}

		// ---- 阶段二：方法级 Pass（指令替换 / 不透明谓词）----
		// 必须在 chain 之后：不透明谓词要包住平坦化产生的块出口，
		// 若放在前面，Flow 会把谓词自己也拆成基本块，反而削弱效果。
		List<Stmt> after = new ArrayList<Stmt>();
		for (Stmt st : ir.stmts) {
			after.add(st);
		}
		if (registry.runMethodPasses(ir, after)) {
			ir.stmts.clear();
			ir.stmts.addAll(after);
		}
	}

	/** 当前启用的模块，供 CLI 打印。 */
	public String describeModules() {
		return registry.describe();
	}
}
