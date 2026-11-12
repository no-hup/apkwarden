package io.apkwarden.core.dex

import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.instruction.*
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference

sealed class RegisterValue {
    data class IntConstant(val value: Int) : RegisterValue()
    data class StringConstant(val value: String) : RegisterValue()
    data class Tainted(val source: TaintSource, val detail: String? = null) : RegisterValue()
    object Unknown : RegisterValue()
}

enum class TaintSource {
    INTENT_EXTRA,
    INTENT_DATA,
    INTENT_OBJECT,
    URI_PATH_SEGMENT,
    ZIP_ENTRY_NAME,
    CLIPBOARD_DATA
}

class MethodAnalyzer(private val method: Method) {

    private val instructions: List<Instruction> = method.implementation?.instructions?.toList() ?: emptyList()
    private val registerStatesAtInstruction: MutableList<Map<Int, RegisterValue>> = mutableListOf()

    init {
        analyze()
    }

    private fun analyze() {
        if (instructions.isEmpty()) return

        val currentRegisters = mutableMapOf<Int, RegisterValue>()

        for (i in instructions.indices) {
            registerStatesAtInstruction.add(currentRegisters.toMap())
            val inst = instructions[i]

            when (inst.opcode) {
                Opcode.CONST_4, Opcode.CONST_16, Opcode.CONST, Opcode.CONST_HIGH16 -> {
                    if (inst is OneRegisterInstruction && inst is NarrowLiteralInstruction) {
                        currentRegisters[inst.registerA] = RegisterValue.IntConstant(inst.narrowLiteral)
                    }
                }
                Opcode.CONST_STRING, Opcode.CONST_STRING_JUMBO -> {
                    if (inst is OneRegisterInstruction && inst is ReferenceInstruction) {
                        val ref = inst.reference
                        if (ref is StringReference) {
                            currentRegisters[inst.registerA] = RegisterValue.StringConstant(ref.string)
                        }
                    }
                }
                Opcode.MOVE, Opcode.MOVE_OBJECT, Opcode.MOVE_16, Opcode.MOVE_OBJECT_16, Opcode.MOVE_FROM16, Opcode.MOVE_OBJECT_FROM16 -> {
                    if (inst is TwoRegisterInstruction) {
                        currentRegisters[inst.registerA] = currentRegisters[inst.registerB] ?: RegisterValue.Unknown
                    }
                }
                Opcode.MOVE_RESULT, Opcode.MOVE_RESULT_OBJECT -> {
                    if (inst is OneRegisterInstruction && i > 0) {
                        val prevInst = instructions[i - 1]
                        val prevTaint = inspectInvocationResult(prevInst)
                        currentRegisters[inst.registerA] = prevTaint ?: RegisterValue.Unknown
                    }
                }
                else -> {
                    // For instructions that overwrite register A without known value, clear it
                    if (inst is OneRegisterInstruction && inst.opcode.canInitializeRegister()) {
                        currentRegisters[inst.registerA] = RegisterValue.Unknown
                    }
                }
            }
        }
    }

    private fun inspectInvocationResult(inst: Instruction): RegisterValue? {
        if (inst !is ReferenceInstruction) return null
        val ref = inst.reference as? MethodReference ?: return null
        val methodName = ref.name
        val defClass = ClassHierarchy.normalizeType(ref.definingClass)

        return when {
            defClass.contains("Intent") && (methodName.startsWith("get") && methodName.contains("Extra")) ->
                RegisterValue.Tainted(TaintSource.INTENT_EXTRA, methodName)
            defClass.contains("Intent") && (methodName == "getData" || methodName == "getDataString") ->
                RegisterValue.Tainted(TaintSource.INTENT_DATA, methodName)
            (defClass.contains("Activity") || defClass.contains("Context")) && methodName == "getIntent" ->
                RegisterValue.Tainted(TaintSource.INTENT_OBJECT, methodName)
            defClass.contains("Uri") && (methodName == "getLastPathSegment" || methodName == "getPath") ->
                RegisterValue.Tainted(TaintSource.URI_PATH_SEGMENT, methodName)
            defClass.contains("ZipEntry") && methodName == "getName" ->
                RegisterValue.Tainted(TaintSource.ZIP_ENTRY_NAME, methodName)
            else -> null
        }
    }

    fun getRegisterValue(reg: Int, instructionIndex: Int): RegisterValue {
        if (instructionIndex !in registerStatesAtInstruction.indices) return RegisterValue.Unknown
        return registerStatesAtInstruction[instructionIndex][reg] ?: RegisterValue.Unknown
    }

    fun getInvocationArgs(instruction: Instruction): List<Int> {
        return when (instruction) {
            is FiveRegisterInstruction -> {
                val count = instruction.registerCount
                val regs = mutableListOf<Int>()
                if (count > 0) regs.add(instruction.registerC)
                if (count > 1) regs.add(instruction.registerD)
                if (count > 2) regs.add(instruction.registerE)
                if (count > 3) regs.add(instruction.registerF)
                if (count > 4) regs.add(instruction.registerG)
                regs
            }
            is RegisterRangeInstruction -> {
                val start = instruction.startRegister
                val count = instruction.registerCount
                (0 until count).map { start + it }
            }
            else -> emptyList()
        }
    }

    fun containsCallTo(targetClass: String, methodName: String): Boolean {
        val normTarget = ClassHierarchy.normalizeType(targetClass)
        return instructions.any { inst ->
            if (inst is ReferenceInstruction) {
                val ref = inst.reference as? MethodReference
                if (ref != null) {
                    val c = ClassHierarchy.normalizeType(ref.definingClass)
                    (c == normTarget || c.endsWith(normTarget)) && ref.name == methodName
                } else false
            } else false
        }
    }

    fun containsStringLiteral(predicate: (String) -> Boolean): Boolean {
        return instructions.any { inst ->
            if (inst is ReferenceInstruction) {
                val ref = inst.reference as? StringReference
                ref != null && predicate(ref.string)
            } else false
        }
    }
}

private fun Opcode.canInitializeRegister(): Boolean {
    return this.flags and Opcode.CAN_INITIALIZE_REFERENCE != 0
}
