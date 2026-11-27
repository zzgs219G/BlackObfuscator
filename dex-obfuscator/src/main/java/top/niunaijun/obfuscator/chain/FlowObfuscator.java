package top.niunaijun.obfuscator.chain;

import com.googlecode.dex2jar.ir.IrMethod;
import com.googlecode.dex2jar.ir.Trap;
import com.googlecode.dex2jar.ir.expr.*;
import com.googlecode.dex2jar.ir.stmt.LabelStmt;
import com.googlecode.dex2jar.ir.stmt.LookupSwitchStmt;
import com.googlecode.dex2jar.ir.stmt.Stmt;
import com.googlecode.dex2jar.ir.stmt.Stmts;
import top.niunaijun.obfuscator.LBlock;
import top.niunaijun.obfuscator.ObfuscatorConfiguration;
import top.niunaijun.obfuscator.RebuildIfResult;
import top.niunaijun.obfuscator.chain.base.BaseObfuscatorChain;

import java.util.*;

public class FlowObfuscator extends BaseObfuscatorChain {

	/** case 表副本数：mask 取值 0..COPIES-1。太大体积会爆，4 已有 4 倍空间。 */
	private static final int COPIES = 4;
	/** 副本间隔。取大值避免不同块的区间重叠。 */
	private static final int SPACE = 0x4000000;

	public FlowObfuscator(ObfuscatorConfiguration obfuscatorConfiguration) {
		super(obfuscatorConfiguration);
	}

	@Override
	public boolean canDepth() {
		return false;
	}

	@Override
	public boolean canHandle(IrMethod ir, Stmt stmt) {
		return true;
	}

	@Override
	public RebuildIfResult reBuild0(IrMethod ir, Stmt stmt, List<Stmt> origStmts) {
		return null;
	}

	@Override
	public void reBuildEnd(IrMethod ir, List<Stmt> newStmts, List<Stmt> origStmts) {
		if (ir.traps.size() > 0 || ir.name.equals("<init>")) {
			newStmts.addAll(origStmts);
			return;
		}
		List<Stmt> orig = new ArrayList<>(origStmts);
		boolean existCallSuper = false;
		List<Stmt> tmp = new ArrayList<>();
		int max = 3;
		for (int i = 0; i < max; i++) {
			if (i > orig.size() - 1) {
				break;
			}
			Stmt stmt = orig.get(i);
			if (stmt.st == Stmt.ST.IDENTITY) {
				max++;
			}
			tmp.add(stmt);
			existCallSuper = isCallSuper(stmt);
			if (existCallSuper) {
				break;
			}
		}
		if (!existCallSuper) {
			orig = new ArrayList<>(origStmts);
		} else {
			newStmts.addAll(tmp);
			for (Stmt stmt : tmp) {
				orig.remove(stmt);
			}
		}

		// ⚠️ 这段是平坦化能被 verifier 接受的关键，不能删：
		//   平坦化把所有原基本块塞进同一个 while 循环，loop head 因此成为
		//   全部块的汇合点。verifier 在该点对每个 slot 做类型合并，只要某个
		//   slot 在部分路径上没写过，合并结果就退化为 UNINITIALIZED_VALUE：
		//     dx: SimException: local 0007: invalid
		//     d8: NegativeArraySizeException
		//   （用 ASM verifier 可精确看到 "Expected an object reference, but found ."）
		//
		//   这里做两件事：
		//     ① 给每个被赋值的局部变量分配【独占】槽位，彻底消除原方法里的
		//        slot 复用（原 dex 里同一个寄存器会承载不同类型的不同变量）。
		//     ② 在方法入口（while 之前）给它们插一条初始化为 0/null 的赋值，
		//        使每个槽位在所有路径上都已初始化，合并结果有定义。
		//   参数槽位（THIS_REF / PARAMETER_REF）不动：JVM 保证入口已初始化。
		Local obfMask = newLocal("obf_mask", "I");
		Local obfSuffixMask = newLocal("obf_suffix_mask", "I");
		Local obfIndexFinal = newLocal("obf_index_final", "I");
		Local obfIndex = newLocal("obf_index", "I");
		Local obfStrHash = newLocal("obf_hash", "I");
		Local obfStr = newLocal("obf_str", "Ljava/lang/String;");

		// 每个局部变量独占槽位 + 入口初始化。必须在 newLocal 之前收集，
		// 否则新 Local 也会被卷进下面的循环里。
		List<Stmt> inits = new ArrayList<>();
		for (Stmt origStmt : orig) {
			if (origStmt.st != Stmt.ST.ASSIGN) {
				continue;
			}
			Stmt.E2Stmt e2Stmt = (Stmt.E2Stmt) origStmt;
			if (e2Stmt.getOp1().vt != Value.VT.LOCAL) {
				continue;
			}
			Local local1 = (Local) e2Stmt.getOp1();
			Value op2 = e2Stmt.getOp2();
			if (op2.vt == Value.VT.THIS_REF || op2.vt == Value.VT.PARAMETER_REF) {
				continue;
			}
			// 独占槽位：原方法里复用的 slot 被拆开，避免同一槽位在不同
			// 路径上承载不同类型。
			local1._ls_index = newLocal("new_local", op2.valueType)._ls_index;
			inits.add(Stmts.nAssign(local1, getNullValue(op2)));
		}

		LBlock whileBlock = generateLBlock();

		List<LBlock> origBlocks = getAllBlock(ir.traps, orig);
		Map<Stmt, LBlock> origBlockMaps = new HashMap<>();
		for (LBlock origBlock : origBlocks) {
			origBlockMaps.put(origBlock.getLabelStmt(), origBlock);
		}

		Set<Stmt> exceptionBlock = new HashSet<>();
		for (LBlock origBlock : origBlocks) {
			if (origBlock.getTrap() != null) {
				exceptionBlock.addAll(Arrays.asList(origBlock.getTrap().handlers));
			}
		}


		List<LBlock> newBlocks = new LinkedList<>();
		LBlock lastBlock = null;
		for (LBlock lBlock : origBlocks) {
			String label = null;
			List<LBlock> tmpBlocks = new ArrayList<>();
			if (!exceptionBlock.contains(lBlock.getLabelStmt())) {
				for (Stmt stmt : lBlock.getStmts()) {
					if (isCallSuper(stmt)) {
						if (lastBlock != null) {
							lastBlock.getStmts().add(stmt);
							continue;
						}
					}
					LBlock newBlock = new LBlock();
					newBlock.getStmts().add(stmt);
					newBlock.setKey(randomString(depth));
					newBlock.setTrap(lBlock.getTrap());
					tmpBlocks.add(newBlock);
					if (label == null) {
						label = newBlock.getKey();
					}
					if (lastBlock != null) {
						lastBlock.setNextKey(newBlock.getKey());
					}
					lastBlock = newBlock;
				}
				newBlocks.addAll(tmpBlocks);

				if (label != null) {
					lBlock.getStmts().clear();
					lBlock.getStmts().add(Stmts.nAssign(obfStr, Exprs.nString(label)));
					lBlock.getStmts().add(Stmts.nGoto(whileBlock.getLabelStmt()));
				}
			}
		}

		LBlock defaultTarget = generateLBlock();
		defaultTarget.getStmts().add(Stmts.nGoto(whileBlock.getLabelStmt()));

		LBlock enter = newBlocks.get(0);
		int obfIndexI = randomString(depth).hashCode();

		newStmts.add(Stmts.nAssign(obfIndexFinal, Exprs.nInt(obfIndexI)));
		newStmts.add(Stmts.nAssign(obfStr, Exprs.nString(enter.getKey())));
		// 入口初始化必须在 while 之前，才能让 loop head 的类型合并有定义。
		newStmts.addAll(inits);
		newStmts.add(whileBlock.getLabelStmt());

		newStmts.add(Stmts.nAssign(obfStrHash, hashInvoke(obfStr)));

		// ⚠️ 状态值混入运行时 mask：这是让「case 值 → 块」静态不可算的关键。
		//
		//   入口：mask = (System.nanoTime() >>> 20) & (COPIES-1)   每方法一次
		//   分发：state = (keyHash ^ obfIndexI) + mask * SPACE
		//
		// case 表里每个块出现 COPIES 份（key+0*SPACE .. key+(COPIES-1)*SPACE），
		// 攻击者即使读到全部 case 值和全部 key，也无法确定运行时落在哪一份 ——
		// mask 来自 nanoTime，静态分析算不出来。
		//
		// 之前所有「不透明谓词」方案都没解决这一点：那些谓词是恒真条件，
		// 攻击者删掉即可，映射关系本身依然是静态可读的。这里改的是映射本身。
		// 全部在 int 层做：long→int 的 cast 在 dex2jar 里容易踩类型坑，
		// 这里直接 (int)nanoTime() 然后按位与，够用且稳。
		CastExpr maskInt = Exprs.nCast(nanoTimeCall(), "J", "I");
		maskInt.valueType = "I";
		newStmts.add(Stmts.nAssign(obfMask,
				typed(Exprs.nAnd(maskInt, typedI(COPIES - 1), "I"))));

		// state = (obfIndexFinal ^ obfStrHash) + mask * SPACE
		newStmts.add(Stmts.nAssign(obfIndex,
				typed(Exprs.nAdd(
						typed(Exprs.nXor(obfIndexFinal, obfStrHash, "I")),
						typed(Exprs.nMul(obfMask, typedI(SPACE), "I")),
						"I"))));

		Map<Integer, LabelStmt> switchBlock = new LinkedHashMap<>();

		// 每个块生成 COPIES 份 case，覆盖 mask 的所有取值
		for (LBlock newBlock : newBlocks) {
			int base = newBlock.getKey().hashCode() ^ obfIndexI;
			for (int c = 0; c < COPIES; c++) {
				switchBlock.put(base + c * SPACE, newBlock.getLabelStmt());
			}
		}
		LookupSwitchStmt lookupSwitchStmt = Stmts.nLookupSwitch(obfIndex,
				switchBlock.keySet().stream().mapToInt(integer -> integer).toArray(),
				switchBlock.values().toArray(new LabelStmt[]{}),
				defaultTarget.getLabelStmt());

		newStmts.add(lookupSwitchStmt);

		newStmts.add(defaultTarget.getLabelStmt());
		newStmts.addAll(defaultTarget.getStmts());

		for (LBlock newBlock : newBlocks) {
			newStmts.add(newBlock.getLabelStmt());
			newStmts.addAll(newBlock.getStmts());

			if (newBlock.getNextKey().length() != 0) {
				Stmt stmt = newBlock.getStmts().get(newBlock.getStmts().size() - 1);
				if (stmt.st != Stmt.ST.GOTO && stmt.st != Stmt.ST.RETURN && stmt.st != Stmt.ST.THROW) {
					// ⚠️ 2026-11-27 修：这里原来还有一句
					//     newStmts.addAll(newBlock.getStmts());
					//   但上面第 179 行已经 add 过了，重复添加会让每个基本块的
					//   指令在字节码里出现两遍 —— 不只是体积翻倍，带副作用的
					//   指令（方法调用、字段写入）会被执行两次，改变程序行为。
					newStmts.add(Stmts.nAssign(obfStr, Exprs.nString(newBlock.getNextKey())));
					newStmts.add(Stmts.nGoto(whileBlock.getLabelStmt()));
				}
			}
		}

		for (LBlock origBlock : origBlocks) {
			newStmts.add(origBlock.getLabelStmt());
			if (!exceptionBlock.contains(origBlock.getLabelStmt())) {
				newStmts.addAll(origBlock.getStmts());
			} else {
				newStmts.add(Stmts.nAssign(obfStr, obfStr));
			}
		}
	}

	private boolean isCallSuper(Stmt stmt) {
		if (stmt.st == Stmt.ST.VOID_INVOKE) {
			Stmt.E1Stmt e1Stmt = (Stmt.E1Stmt) stmt;
			InvokeExpr expr = (InvokeExpr) e1Stmt.getOp();
			return "<init>".equals(expr.method.getName());
		}
		return false;
	}

	/**
	 * System.nanoTime()。每次调用返回不同值，静态分析无法定值。
	 * 用它派生 mask，使 case 值 → 块的映射依赖运行时状态。
	 */
	/** 给表达式补上 valueType（IR2JConverter 的 getOpcode 依赖它）。 */
	private static Value typed(BinopExpr e) {
		e.valueType = e.vt == Value.VT.USHR ? "J" : "I";
		return e;
	}

	private static Constant typedI(int v) {
		Constant c = Exprs.nInt(v);
		c.valueType = "I";
		return c;
	}

	private InvokeExpr nanoTimeCall() {
		InvokeExpr e = Exprs.nInvokeStatic(new Value[]{}, "Ljava/lang/System;",
				"nanoTime", new String[]{}, "J");
		e.valueType = "J";
		return e;
	}

	private InvokeExpr hashInvoke(Local strLocal) {
		return Exprs.nInvokeVirtual(new Value[]{strLocal}, "Ljava/lang/String;","hashCode", new String[]{}, "I");
	}

	private LBlock generateLBlock() {
		return new LBlock();
	}

	private List<LBlock> getAllBlock(List<Trap> traps, List<Stmt> origStmts) {
		List<LBlock> blocks = new ArrayList<>();
		LBlock lBlock = new LBlock();
		Trap trap = null;
		for (Stmt origStmt : origStmts) {
			if (origStmt.st == Stmt.ST.LABEL) {
				for (Trap t : traps) {
					if (t.start == origStmt || t.end == origStmt) {
						trap = t;
						break;
					} else {
						trap = null;
					}
				}
				blocks.add(lBlock);
				lBlock = new LBlock((LabelStmt) origStmt);
				if (trap != null) {
					lBlock.setTrap(trap);
				}
			} else {
				lBlock.getStmts().add(origStmt);
			}
		}
		blocks.add(lBlock);
		return blocks;
	}

	private Value getNullValue(Value value) {
		Constant constant = null;
		switch (value.valueType) {
			case "I":
				constant = Exprs.nInt(0);
				break;
			case "S":
				constant = Exprs.nShort((short) 0);
				break;
			case "J":
				constant = Exprs.nLong(0);
				break;
			case "F":
				constant = Exprs.nFloat(0);
				break;
			case "D":
				constant = Exprs.nDouble(0);
				break;
			case "C":
				constant = Exprs.nChar((char) 0);
				break;
			case "B":
				constant = Exprs.nByte((byte) 0);
				break;
			case "Z":
				constant = new Constant(false);
				break;
		}
		if (constant == null) {
			constant = new Constant(Constant.Null);
		}
		constant.valueType = value.valueType;
		return constant;
	}
}
