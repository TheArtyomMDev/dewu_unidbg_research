package com.shizhuang.dusanwa.main;


import com.github.unidbg.arm.backend.Backend;
import unicorn.Arm64Const;

import java.util.List;

public class ConditionEvaluator {

    /**
     * Оценивает условие ARM64 на основе флагов PSTATE
     * @param condition Строка условия (EQ, NE, GT, LT и т.д.)
     * @return true если условие выполняется, false иначе
     */
    public static boolean evaluateCondition(String condition, Backend backend) {
        long pstate = readPSTATE(backend);
        Flags flags = extractFlagsFromPSTATE(pstate);
        return evaluateConditionWithFlags(condition, flags);
    }

    /**
     * Читает значение регистра PSTATE напрямую из эмулятора
     */
    private static long readPSTATE(Backend backend) {
        try {
            // В ARM64 PSTATE обычно доступен через специальный регистр
            // В unidbg это может быть реализовано как отдельный регистр
            return backend.reg_read(Arm64Const.UC_ARM64_REG_NZCV).longValue();
        } catch (Exception e) {
            System.err.println("Could not read PSTATE register: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * Извлекает флаги N, Z, C, V из значения PSTATE
     */
    private static Flags extractFlagsFromPSTATE(long pstate) {
        Flags flags = new Flags();

        // ARM64 PSTATE флаги (в порядке старшинства):
        // N (Negative) - бит 31
        // Z (Zero) - бит 30
        // C (Carry) - бит 29
        // V (Overflow) - бит 28

        flags.N = ((pstate >> 31) & 1) == 1;
        flags.Z = ((pstate >> 30) & 1) == 1;
        flags.C = ((pstate >> 29) & 1) == 1;
        flags.V = ((pstate >> 28) & 1) == 1;

        return flags;
    }

    /**
     * Оценивает условие на основе извлеченных флагов
     */
    private static boolean evaluateConditionWithFlags(String condition, Flags flags) {
        return switch (condition.toUpperCase()) {
            case "EQ" -> flags.Z;
            case "NE" -> !flags.Z;
            case "CS", "HS" -> flags.C;
            case "CC", "LO" -> !flags.C;
            case "MI" -> flags.N;
            case "PL" -> !flags.N;
            case "VS" -> flags.V;
            case "VC" -> !flags.V;
            case "HI" -> flags.C && !flags.Z;
            case "LS" -> !flags.C || flags.Z;
            case "GE" -> flags.N == flags.V;
            case "LT" -> flags.N != flags.V;
            case "GT" -> !flags.Z && (flags.N == flags.V);
            case "LE" -> flags.Z || (flags.N != flags.V);
            case "AL" -> true;
            default -> {
                System.err.println("Unknown condition: " + condition);
                throw new RuntimeException("Unknown condition: " + condition);
            }
        };
    }

    /**
     * Вспомогательный класс для хранения флагов ARM64
     */
    public static class Flags {
        public boolean N; // Negative
        public boolean Z; // Zero
        public boolean C; // Carry
        public boolean V; // Overflow

        @Override
        public String toString() {
            return String.format("N=%b, Z=%b, C=%b, V=%b", N, Z, C, V);
        }
    }
}