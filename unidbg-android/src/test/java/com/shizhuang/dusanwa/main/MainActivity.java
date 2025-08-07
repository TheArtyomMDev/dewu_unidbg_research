package com.shizhuang.dusanwa.main;

import capstone.Capstone;
import capstone.api.Instruction;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.*;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.jni.ProxyClassFactory;
import com.github.unidbg.memory.Memory;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.Arm64Const;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.shizhuang.dusanwa.main.ConditionEvaluator.evaluateCondition;
import static java.lang.Math.abs;

public class MainActivity {

    private final AndroidEmulator emulator;

    private final DvmClass cSignUtil;

    private final VM vm;
    private Module module;
    private static String srcName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/libdusanwa_src.so";
    private static String inName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/libdusanwa_ext.so";
    private static String outName = "unidbg-android/src/test/resources/example_binaries/arm64-v8a/libdusanwa_ext_patched.so";
    private HashMap<Long, LinkedHashSet<PatchIns>> patches = new HashMap<>();
    private Stack<InsAndCtx> instructions = new Stack<>();

    static boolean isTrackingToNextJump = false;
    static long savedJumpAddress = 0;
    static int beginFunc = 0x9F6C; // Начальный адрес функции, которую мы хотим отслеживать
    static int dispatcherAddress = 0xA084;
    static int endFunc = 0xCF14;

    long resultPtr = 0;
    long resultSz = 0;

    public MainActivity(String libPath, boolean doPatch) {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.shizhuang.duapp")
                .addBackendFactory(new HypervisorFactory(true))
//                .addBackendFactory(new DynarmicFactory(true))
                .addBackendFactory(new KvmFactory(true))
                .build();

        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM();
        vm.setDvmClassFactory(new ProxyClassFactory());
        vm.setVerbose(doPatch);
        DalvikModule dm = vm.loadLibrary(new File(libPath), false);
        module = dm.getModule();
        cSignUtil = vm.resolveClass("com/shizhuang/dusanwa/main/SwSdk");
        dm.callJNI_OnLoad(emulator);

        if (!doPatch) {
//            emulator.traceCode(dm.getModule().base + beginFunc, dm.getModule().base + endFunc);
            return;
        }

        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);
                byte[] bytes = emulator.getBackend().mem_read(address, 4);
                Instruction[] disasm = capstone.disasm(bytes, 0);
                InsAndCtx iac = new InsAndCtx();
                iac.setIns(disasm[0]);
                iac.setRegs(saveRegs(backend));
                iac.setAddr(address);

                instructions.push(iac);
                do_processbr();
            }

            @Override
            public void onAttach(UnHook unHook) {
                System.out.println("attach");
            }

            @Override
            public void detach() {
                System.out.println("detach");
            }
        }, module.base + beginFunc, module.base + endFunc, null);

        final long trackingFunc = module.base + 0x9F6C;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                long arg0 = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                long arg1 = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
                long arg2 = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
                long arg3 = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).longValue();
                long arg4 = backend.reg_read(Arm64Const.UC_ARM64_REG_X4).longValue();
                long arg5 = backend.reg_read(Arm64Const.UC_ARM64_REG_X5).longValue();
                long arg6 = backend.reg_read(Arm64Const.UC_ARM64_REG_X6).longValue();

                System.out.format(
                        "sub_9F6C args: x0=%#x, x1=%#x, x2=%#x\n",
                        arg0, arg1, arg2
                );
                resultPtr = arg1;
                resultSz = 8;

//                System.out.println("x0: " + readCString(arg0));
                System.out.println("x0: " + Arrays.toString(readMemory(arg0, 8)));
//                System.out.println("x1: " + readCString(arg1));
//                System.out.println("x2: " + readCString(arg2));
                byte[] data = readMemory(arg2, 104);
                System.out.println("x2: " + Arrays.toString(data));

                System.out.println("x2 str: " + Base64.getEncoder().encodeToString(data));
//                data[100] = 0;
//                for (int i = 0; i < 8; i++) {
//                    data[i] = 0; // Заполняем нулями, чтобы не мешать работе
//                }
//                data[28] = 12;
//                writeMemory(arg2, data); // Заполняем нулями, чтобы не мешать работе


//                System.out.println("x0: " + Arrays.toString(readMemory(arg0, 16)));
//                System.out.println("x0 str: " + new String(readMemory(arg0, 16), StandardCharsets.UTF_8));
//                System.out.println("x6: " + readCString(arg6));
            }

            @Override
            public void onAttach(UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, trackingFunc, trackingFunc, null);

        final long trackingFunc2 = module.base + 0xCF14;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                System.out.println("resultPtr: " + Arrays.toString(readMemory(resultPtr, resultSz)));
                System.out.println("resultPtr str: " + new String(readMemory(resultPtr, resultSz), StandardCharsets.UTF_8));
            }

            @Override
            public void onAttach(UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, trackingFunc2, trackingFunc2, null);

        final long trackingFunc3 = module.base + 0xCF18;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                long arg0 = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                long arg1 = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
                long arg2 = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
                long arg3 = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).longValue();
                long arg4 = backend.reg_read(Arm64Const.UC_ARM64_REG_X4).longValue();
                long arg5 = backend.reg_read(Arm64Const.UC_ARM64_REG_X5).longValue();
                long arg6 = backend.reg_read(Arm64Const.UC_ARM64_REG_X6).longValue();

                System.out.format(
                        "sub_CF18 args: x0=%#x, x1=%#x, x2=%#x, x3=%#x\n",
                        arg0, arg1, arg2, arg3
                );
                resultPtr = arg2;
                resultSz = arg1;

                System.out.println("x0: " + readCString(arg0));
                System.out.println("x2: " + readCString(arg2));
                System.out.println("x3: " + readCString(arg3));
                System.out.println("x3: " + Arrays.toString(readMemory(arg3, 16)));
                System.out.println("x3 str: " + Base64.getEncoder().encodeToString(readMemory(arg3, 16)));
//                System.out.println("x0: " + Arrays.toString(readMemory(arg0, 16)));
//                System.out.println("x0 str: " + new String(readMemory(arg0, 16), StandardCharsets.UTF_8));
//                System.out.println("x6: " + readCString(arg6));
            }

            @Override
            public void onAttach(UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, trackingFunc3, trackingFunc3, null);
//
//        final long trackingFunc2 = module.base + 0xDB70;
//        emulator.getBackend().hook_add_new(new CodeHook() {
//            @Override
//            public void hook(Backend backend, long address, int size, Object user) {
////                System.out.println("resultPtr: " + readCString(resultPtr));
//                System.out.println("resultPtr: " + Arrays.toString(readMemory(resultPtr, resultSz)));
////                System.out.println("resultPtr 1: " + Arrays.toString(readMemory(resultPtr + 8, 16)));
//                System.out.println("resultPtr str: " + new String(readMemory(resultPtr, resultSz), StandardCharsets.UTF_8));
////                System.out.println("resultPtr str 1: " + new String(readMemory(resultPtr + 1, 16), StandardCharsets.UTF_8));
//            }
//
//            @Override public void onAttach(UnHook unHook) {}
//            @Override public void detach() {}
//        }, trackingFunc2, trackingFunc2, null);

        /*
        final long trackingFunc = module.base + 0x1D2C4;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                long arg0 = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                long arg1 = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
                long arg2 = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
//                long arg3 = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).longValue();
//                long arg4 = backend.reg_read(Arm64Const.UC_ARM64_REG_X4).longValue();
//                long arg5 = backend.reg_read(Arm64Const.UC_ARM64_REG_X5).longValue();
//                long arg6 = backend.reg_read(Arm64Const.UC_ARM64_REG_X6).longValue();
                System.out.format(
                        "sub_1D2C4 args: x0=%#x, x1=%#x, x2=%#x\n",
                        arg0, arg1, arg2
                );
                resultPtr = arg0;
                resultSz = arg2;

                System.out.println("x0: " + readCString(arg0));
                System.out.println("x1: " + Arrays.toString(readMemory(arg1, arg2)));
                System.out.println("x1 str: " + new String(readMemory(arg1, arg2), StandardCharsets.UTF_8));
//                System.out.println("x6: " + readCString(arg6));
            }

            @Override public void onAttach(UnHook unHook) {}
            @Override public void detach() {}
        }, trackingFunc, trackingFunc, null);

        final long trackingFunc2 = module.base + 0x1DAE0;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
//                System.out.println("resultPtr: " + readCString(resultPtr));
                System.out.println("resultPtr: " + Arrays.toString(readMemory(resultPtr, resultSz)));
                System.out.println("resultPtr 1: " + Arrays.toString(readMemory(resultPtr + 8, 16)));
//                System.out.println("resultPtr str: " + new String(readMemory(resultPtr, resultSz), StandardCharsets.UTF_8));
//                System.out.println("resultPtr str 1: " + new String(readMemory(resultPtr + 1, 16), StandardCharsets.UTF_8));
            }

            @Override public void onAttach(UnHook unHook) {}
            @Override public void detach() {}
        }, trackingFunc2, trackingFunc2, null);
        */
    }

    public byte[] readMemory(long address, long length) {
        return emulator.getBackend().mem_read(address, length);
    }

    public void writeMemory(long address, byte[] data) {
        emulator.getBackend().mem_write(address, data);
    }

    // Читает C-строку (null-terminated) из памяти по адресу address
    public String readCString(long address) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte b;
        do {
            b = emulator.getBackend().mem_read(address++, 1)[0];
            if (b != 0) {
                baos.write(b);
            }
        } while (b != 0);
        return baos.toString(StandardCharsets.UTF_8);
    }

    public List<Number> saveRegs(Backend bk) {
        List<Number> nb = new ArrayList<>();
        for (int i = 0; i < 29; i++) {
            nb.add(bk.reg_read(i + Arm64Const.UC_ARM64_REG_X0));
        }
        nb.add(bk.reg_read(Arm64Const.UC_ARM64_REG_FP));
        nb.add(bk.reg_read(Arm64Const.UC_ARM64_REG_LR));
        return nb;
    }

    public Number getRegValue(String reg, List<Number> regs) {
        if ("zr".equals(reg) || "xzr".equals(reg) || "wzr".equals(reg)) {
            return 0L;
        }

        if (reg.startsWith("x") || reg.startsWith("w")) {
            int index = Integer.parseInt(reg.substring(1));
            if (index >= 0 && index < regs.size()) {
                return regs.get(index);
            } else {
                throw new IllegalArgumentException("Invalid register index: " + index);
            }
        } else if (reg.equals("fp")) {
            return regs.get(29);
        } else if (reg.equals("lr")) {
            return regs.get(30);
        } else {
            throw new IllegalArgumentException("Unknown register: " + reg);
        }
    }

    public long readInt64(long address) {
        byte[] bytes = emulator.getBackend().mem_read(address, 8);
        return ((bytes[0] & 0xFFL) << 56) |
                ((bytes[1] & 0xFFL) << 48) |
                ((bytes[2] & 0xFFL) << 40) |
                ((bytes[3] & 0xFFL) << 32) |
                ((bytes[4] & 0xFFL) << 24) |
                ((bytes[5] & 0xFFL) << 16) |
                ((bytes[6] & 0xFFL) << 8) |
                (bytes[7] & 0xFFL);
    }

    public void addPatch(PatchIns patchIns) {
        if (!patches.containsKey(patchIns.getAddr())) {
            patches.put(patchIns.getAddr(), new LinkedHashSet<>());
        }

        for (PatchIns p : patches.get(patchIns.getAddr())) {
            if (p.getIns().equals(patchIns.getIns())) {
                return; // Патч уже существует, не добавляем повторно
            }
        }
        patches.get(patchIns.getAddr()).add(patchIns);
    }

    public void do_processbr() {
        try {
            Instruction ins = instructions.peek().getIns();
            String mnemonic = ins.getMnemonic().trim().toLowerCase(Locale.ROOT);
            long insAddress = instructions.peek().getAddr() - module.base;

            /*
            if (mnemonic.equals("csel")) {
                String[] sp = ins.getOpStr().toLowerCase(Locale.ROOT).split(",");
                if (sp.length == 4) {
                    String dest = sp[0].trim();
                    String val1 = sp[1].trim();
                    String val2 = sp[2].trim();
                    String cond = sp[3].trim();

                    // Получаем значения регистров
                    long val1Value = getRegValue(val1, instructions.peek().getRegs()).longValue();
                    long val2Value = getRegValue(val2, instructions.peek().getRegs()).longValue();

                    // Ключевое изменение: используем PSTATE для оценки условия
                    boolean conditionTrue = ConditionEvaluator.evaluateCondition(cond, emulator.getBackend());

                    long chosenValue = conditionTrue ? val1Value : val2Value;
                    String chosenReg = conditionTrue ? val1 : val2;

                    // Создаем комментарий с пояснением
                    long addr = (instructions.peek().getAddr() - module.base);
                    String comment = String.format(
                            "0x%s; CSEL %s, %s, %s, %s => %s = 0x%X (%s выбран)",
                            Long.toHexString(addr),
                            dest, val1, val2, cond, dest, chosenValue, chosenReg);

                    // Заменяем CSEL на MOV
                    PatchIns patch = new PatchIns();
                    patch.setAddr(addr);

//                    if (0 <= chosenValue && chosenValue <= 0xFFL) {
//                        patch.setIns(String.format("mov %s, #%d", dest, chosenValue));
//                    } else {
                        patch.setIns(String.format("mov %s, %s", dest, chosenReg));
//                    }

                    addPatch(patch);
                }
            }
            */

            /*
            if (mnemonic.startsWith("b.")) {
                String[] sp = ins.getOpStr().toLowerCase(Locale.ROOT).split(",");
                if (sp.length == 1) {
                    String dest = sp[0].trim();

                    long offset;
                    if (dest.startsWith("#")) {
                        dest = dest.substring(3);
                        offset = new BigInteger(dest, 16).longValue();
                    } else {
                        offset = getRegValue(dest, instructions.peek().getRegs()).longValue();
                    }

                    String cond = mnemonic.substring(2).trim();
                    boolean conditionTrue = ConditionEvaluator.evaluateCondition(cond, emulator.getBackend());

                    PatchIns patch = new PatchIns();
                    patch.setAddr(insAddress);
                    if (conditionTrue) {
                        patch.setIns(String.format("b #%d", offset));
                    } else {
                        patch.setIns("nop"); // Если условие не выполняется, заменяем на NOP
                    }

                    addPatch(patch);
                }
            }
            */


            boolean isJumpInstruction = false;
            if (
                    !mnemonic.contains("cmp")
                            && !mnemonic.equals("mov")
                            && !mnemonic.equals("movz")
                            && !mnemonic.equals("movk")
                            && !mnemonic.equals("b")
                            && !mnemonic.contains("b.")
                            && !mnemonic.equals("nop")
//                    && !mnemonic.startsWith("ldr")
//                    && !mnemonic.startsWith("str")
                            && !mnemonic.equals("csel")
            ) {
                isJumpInstruction = true;
            } else if (
                    mnemonic.equals("mov")
                            || mnemonic.equals("movz")
                            || mnemonic.equals("movk")
                            || mnemonic.contains("cmp")
//                            || mnemonic.startsWith("ldr")
//                            || mnemonic.startsWith("str")
                            || mnemonic.startsWith("csel")
            ) {
                String[] sp = ins.getOpStr().toLowerCase(Locale.ROOT).split(",");

                isJumpInstruction = true;
                for (String s : sp) {
                    if (s.contains("w5") || s.contains("w8") || s.contains("w15")) {
                        isJumpInstruction = false; // Игнорируем инструкции, связанные с w8 и w9
                        break;
                    }
                }
            }

            {
                if (insAddress >= 0x24FFC && insAddress <= 0x25018) {
                    isJumpInstruction = false;
                }
            }

            //  System.out.printf("0x%x %s %s\n", instructions.peek().getAddr() - module.base, ins.getMnemonic(), ins.getOpStr());

            if (isJumpInstruction) {
                if (isTrackingToNextJump) {
                    System.out.printf("Processing instruction: 0x%x %s %s\n", instructions.peek().getAddr() - module.base, ins.getMnemonic(), ins.getOpStr());
                    isTrackingToNextJump = false;

                    long currentAddress = instructions.peek().getAddr() - module.base;
                    long difference = currentAddress - savedJumpAddress;

                    PatchIns patch = new PatchIns();
                    patch.setAddr(savedJumpAddress);
                    patch.setIns("b " + String.format("#0x%016x", difference));
                    System.out.format("Adding patch: 0x%x b 0x%x\n", patch.addr, currentAddress);
                    addPatch(patch);
                }
            }

            if (mnemonic.equals("b")) {
                String[] sp = ins.getOpStr().toLowerCase(Locale.ROOT).split(",");
                String opStr = sp[0].startsWith("#") ? sp[0].substring(1) : sp[0];

                try {
                    if (opStr.startsWith("0x")) {
                        opStr = opStr.substring(2); // Убираем "0x"
                    }
                    BigInteger bigValue = new BigInteger(opStr, 16);
                    long jmpAddr = insAddress + bigValue.longValue();

                    if (jmpAddr == dispatcherAddress && !isTrackingToNextJump) {
                        isTrackingToNextJump = true;
                        savedJumpAddress = insAddress;
                    }

                    System.out.printf("0x%x: b → 0x%x\n", insAddress, jmpAddr);
                } catch (NumberFormatException e) {
                    System.err.println("Ошибка парсинга адреса: " + opStr);
                }

            }


        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void destroy() throws IOException {
        emulator.close();
    }

    public String achilles(byte[] p1) {
        Object[] arr_object = {p1};


        ByteArray byteArray0 = (ByteArray) cSignUtil.callStaticJniMethodObject(emulator, "achilles([B)[B", arr_object);
        byte[] arr_b = new byte[byteArray0.length()];
        for (int v = 0; v < byteArray0.length(); ++v) {
            arr_b[v] = ((byte[]) byteArray0.getValue())[v];
        }

        return Base64.getEncoder().encodeToString(arr_b);
    }

    public static void main(String[] args) throws Exception {
        String[] testArgs = new String[]{
                "bye bye",
                "i am the bitch",
                "fuck you i am so cool so long striiiingas"
        };

        MainActivity signUtilLatest = new MainActivity(inName, true);
        String oldSign = signUtilLatest.achilles(testArgs[0].getBytes(StandardCharsets.UTF_8));
        signUtilLatest.patch();
        System.out.println("patch done, now test achilles again");
        System.out.println(oldSign);

        for (String arg : testArgs) {
            byte[] testString = arg.getBytes(StandardCharsets.UTF_8);

            MainActivity signUtilSrc = new MainActivity(srcName, false);
            String origSign = signUtilSrc.achilles(testString);
            System.out.println(origSign);

            MainActivity signUtilPatched = new MainActivity(outName, false);
            String signToTest = signUtilPatched.achilles(testString);
            System.out.println(signToTest);

            signUtilSrc.destroy();
            signUtilPatched.destroy();

            if (!origSign.equals(signToTest)) {
                throw new RuntimeException("sign fail");
            }
        }

        signUtilLatest.destroy();
//        byte[] p1 =  "hi".getBytes(StandardCharsets.UTF_8);
//
//        MainActivity signUtil = new MainActivity(inName, true);
//        String sign = signUtil.achilles(p1);
//        System.out.println(sign);
//        signUtil.patch();
//
//
//        MainActivity signUtil2 = new MainActivity(outName, false);
//        System.out.println("patch done, now test achilles again");
//        String sign2 = signUtil2.achilles(p1);
//        System.out.println(sign2);
//
//        signUtil.destroy();
//        signUtil2.destroy();
//
//        if (!sign.equals(sign2)) {
//            throw new RuntimeException("sign fail");
//        }
    }

    public void patch() {
        try {
            File f = new File(inName);
            FileInputStream fis = new FileInputStream(f);
            byte[] data = new byte[(int) f.length()];
            fis.read(data);
            fis.close();
            for (Map.Entry<Long, LinkedHashSet<PatchIns>> entry : patches.entrySet()) {
                if (entry.getValue().size() == 1) {
                    PatchIns pi = entry.getValue().iterator().next();
                    System.out.println("procrss addr: " + Integer.toHexString((int) pi.addr) + ", code:" + pi.getIns());
                    Keystone ks = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian);
                    KeystoneEncoded assembly = ks.assemble(pi.getIns());
                    for (int i = 0; i < assembly.getMachineCode().length; i++) {
                        data[(int) pi.addr + i] = assembly.getMachineCode()[i];
                    }
                }
            }
//            for (PatchIns pi : patches) {
//                System.out.println("procrss addr:" + Integer.toHexString((int) pi.addr) + ",code:" + pi.getIns());
//                Keystone ks = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian);
//                KeystoneEncoded assembly = ks.assemble(pi.getIns());
//                for (int i = 0; i < assembly.getMachineCode().length; i++) {
//                    data[(int) pi.addr + i] = assembly.getMachineCode()[i];
//                }
//            }
            File fo = new File(outName);
            FileOutputStream fos = new FileOutputStream(fo);
            fos.write(data);
            fos.flush();
            fos.close();
            System.out.println("finish");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

