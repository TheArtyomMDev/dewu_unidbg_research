package com.shizhuang.dusanwa.main;

import capstone.api.Instruction;

import java.util.List;
import java.util.Objects;

class InsAndCtx {
    long addr;
    Instruction ins;
    List<Number> regs;

    public long getAddr() {
        return addr;
    }

    public void setAddr(long addr) {
        this.addr = addr;
    }

    public void setIns(Instruction ins) {
        this.ins = ins;
    }

    public Instruction getIns() {
        return ins;
    }

    public void setRegs(List<Number> regs) {
        this.regs = regs;
    }

    public List<Number> getRegs() {
        return regs;
    }
}

//patch class 
class PatchIns {
    long addr;//patch address
    String ins;
//    Instructions for ;//patch

    public long getAddr() {
        return addr;
    }

    public void setAddr(long addr) {
        this.addr = addr;
    }

    public String getIns() {
        return ins;
    }

    public void setIns(String ins) {
        this.ins = ins;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        PatchIns other = (PatchIns) obj;
        if (addr != other.addr) {
            return false;
        }
        return Objects.equals(ins, other.ins);
    }
}