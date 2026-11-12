package io.apkwarden.core.dex

import com.android.tools.smali.dexlib2.AccessFlags
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
        val impl = method.implementation ?: return
        if (instructions.isEmpty()) return

        val currentRegisters = mutableMapOf<Int, RegisterValue>()
        seedMethodParameters(currentRegisters, impl.registerCount)

        for (i in instructions.indices) {
            registerStatesAtInstruction.add(currentRegisters.toMap())
            val inst = instructions[i]

            when (inst.opcode) {
                // Constant integers
                Opcode.CONST_4, Opcode.CONST_16, Opcode.CONST, Opcode.CONST_HIGH16 -> {
                    if (inst is OneRegisterInstruction && inst is NarrowLiteralInstruction) {
                        currentRegisters[inst.registerA] = RegisterValue.IntConstant(inst.narrowLiteral)
                    }
                }
                // Constant strings
                Opcode.CONST_STRING, Opcode.CONST_STRING_JUMBO -> {
                    if (inst is OneRegisterInstruction && inst is ReferenceInstruction) {
                        val ref = inst.reference
                        if (ref is StringReference) {
                            currentRegisters[inst.registerA] = RegisterValue.StringConstant(ref.string)
                        }
                    }
                }
                // Move operations: register copy
                Opcode.MOVE, Opcode.MOVE_OBJECT, Opcode.MOVE_16, Opcode.MOVE_OBJECT_16, Opcode.MOVE_FROM16, Opcode.MOVE_OBJECT_FROM16 -> {
                    if (inst is TwoRegisterInstruction) {
                        currentRegisters[inst.registerA] = currentRegisters[inst.registerB] ?: RegisterValue.Unknown
                    }
                }
                // Move result of an invocation
                Opcode.MOVE_RESULT, Opcode.MOVE_RESULT_OBJECT -> {
                    if (inst is OneRegisterInstruction && i > 0) {
                        val prevInst = instructions[i - 1]
                        val prevTaint = inspectInvocationResult(prevInst)
                        currentRegisters[inst.registerA] = prevTaint ?: RegisterValue.Unknown
                    }
                }
                // Check-cast asserts type but preserves reference and taint in registerA
                Opcode.CHECK_CAST -> {
                    // Intentionally do not clear registerA; keep existing value/taint
                }
                // Any other instruction that sets registerA: clear destination register to Unknown
                else -> {
                    if (inst.opcode.setsRegister() || inst.opcode.setsWideRegister()) {
                        val destReg = when (inst) {
                            is OneRegisterInstruction -> inst.registerA
                            is TwoRegisterInstruction -> inst.registerA
                            is ThreeRegisterInstruction -> inst.registerA
                            else -> null
                        }
                        if (destReg != null) {
                            currentRegisters[destReg] = RegisterValue.Unknown
                        }
                    }
                }
            }
        }
    }

    private fun seedMethodParameters(currentRegisters: MutableMap<Int, RegisterValue>, totalRegs: Int) {
        val paramTypes = method.parameterTypes.map { it.toString() }
        val isStatic = (method.accessFlags and AccessFlags.STATIC.value) != 0

        var paramRegCount = if (!isStatic) 1 else 0
        for (pt in paramTypes) {
            paramRegCount += if (pt == "J" || pt == "D") 2 else 1
        }

        var currentReg = totalRegs - paramRegCount
        if (!isStatic) {
            // Register p0 is 'this'
            currentReg += 1
        }

        for (pt in paramTypes) {
            val norm = ClassHierarchy.normalizeType(pt)
            when {
                norm == "android.content.Intent" -> {
                    currentRegisters[currentReg] = RegisterValue.Tainted(TaintSource.INTENT_OBJECT, "method parameter")
                }
                norm == "android.net.Uri" -> {
                    currentRegisters[currentReg] = RegisterValue.Tainted(TaintSource.URI_PATH_SEGMENT, "method parameter")
                }
            }
            currentReg += if (pt == "J" || pt == "D") 2 else 1
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
            defClass.contains("Uri") && (methodName == "getLastPathSegment" || methodName == "getPath" || methodName == "getQueryParameter") ->
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

    /**
     * Checks whether an Intent passed to a sink was sanitized (package or component validated).
     */
    fun hasIntentSanitization(): Boolean {
        return containsCallTo("android.content.Intent", "setPackage") ||
                containsCallTo("android.content.Intent", "setComponent") ||
                containsCallTo("android.content.Intent", "setClass") ||
                containsCallTo("android.content.Intent", "setClassName") ||
                containsCallTo("android.content.ComponentName", "getPackageName") ||
                containsCallTo("android.content.Context", "getPackageName")
    }

    /**
     * Checks whether a path derived from Uri or zip was sanitized (canonical path check or File.getName()).
     */
    fun hasPathSanitization(): Boolean {
        return containsCallTo("java.io.File", "getCanonicalPath") ||
                containsCallTo("java.io.File", "getCanonicalFile") ||
                containsCallTo("java.io.File", "getName")
    }

    /**
     * Extracts a contextual Dalvik disassembly snippet centered around target instruction index.
     */
    fun getDisassemblySnippet(targetIndex: Int, window: Int = 2): String {
        if (instructions.isEmpty()) return ""
        val start = (targetIndex - window).coerceAtLeast(0)
        val end = (targetIndex + window).coerceAtMost(instructions.size - 1)
        val sb = StringBuilder()
        for (i in start..end) {
            val prefix = if (i == targetIndex) "> " else "  "
            val inst = instructions[i]
            val offset = "%04x".format(i)
            val op = inst.opcode.name
            val refStr = if (inst is ReferenceInstruction) {
                when (val ref = inst.reference) {
                    is MethodReference -> " ${ref.definingClass}->${ref.name}"
                    is StringReference -> {
                        val raw = ref.string
                        val display = if ((raw.startsWith("AKIA") || raw.startsWith("AIza") || raw.startsWith("xox")) && raw.length > 8) {
                            "${raw.take(4)}...${raw.takeLast(4)}"
                        } else raw
                        " \"$display\""
                    }
                    is com.android.tools.smali.dexlib2.iface.reference.FieldReference -> " ${ref.definingClass}->${ref.name}:${ref.type}"
                    is com.android.tools.smali.dexlib2.iface.reference.TypeReference -> " ${ref.type}"
                    else -> ""
                }
            } else ""
            sb.append("$prefix$offset: $op$refStr")
            if (i < end) sb.append("\n")
        }
        return sb.toString()
    }
}
