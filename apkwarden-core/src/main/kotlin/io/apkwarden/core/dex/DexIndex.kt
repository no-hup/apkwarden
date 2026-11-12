package io.apkwarden.core.dex

import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.FieldReference
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import io.apkwarden.core.ingest.ApkArchive
import io.apkwarden.core.model.AttackSurface

data class CallSite(
    val callerClass: String,
    val callerMethod: String,
    val callerMethodSig: String,
    val targetClass: String,
    val targetMethod: String,
    val targetSig: String,
    val instructionIndex: Int,
    val instruction: Instruction,
    val dexName: String,
    val method: Method
)

data class StringOccurrence(
    val string: String,
    val callerClass: String,
    val callerMethod: String,
    val instructionIndex: Int,
    val dexName: String,
    val method: Method
)

data class FieldAccess(
    val callerClass: String,
    val callerMethod: String,
    val targetClass: String,
    val fieldName: String,
    val fieldType: String,
    val instructionIndex: Int,
    val instruction: Instruction,
    val dexName: String,
    val method: Method
)

data class IndexedMethod(
    val definingClass: String,
    val rawDefiningClass: String,
    val name: String,
    val returnType: String,
    val parameterTypes: List<String>,
    val accessFlags: Int,
    val method: Method,
    val dexName: String
)

class DexIndex private constructor(
    val classDefs: Map<String, ClassDef>,
    val methods: List<IndexedMethod>,
    val hierarchy: ClassHierarchy,
    private val callSitesByTarget: Map<String, List<CallSite>>,
    private val stringOccurrences: Map<String, List<StringOccurrence>>,
    private val fieldAccesses: Map<String, List<FieldAccess>>,
    private val callersByMethod: Map<String, Set<String>>
) {

    fun findCallSites(targetClass: String, targetMethod: String): List<CallSite> {
        val normTarget = ClassHierarchy.normalizeType(targetClass)
        val key = "$normTarget#$targetMethod"
        val exactCalls = callSitesByTarget[key] ?: emptyList()

        // Also find calls to subclasses or superclasses if virtual dispatch
        val virtualCalls = mutableListOf<CallSite>()
        for ((k, sites) in callSitesByTarget) {
            val parts = k.split('#')
            if (parts.size == 2 && parts[1] == targetMethod) {
                val callTargetClass = parts[0]
                if (callTargetClass != normTarget && hierarchy.isSubclassOf(callTargetClass, normTarget)) {
                    virtualCalls.addAll(sites)
                }
            }
        }

        return exactCalls + virtualCalls
    }

    fun findStringLiterals(predicate: (String) -> Boolean): List<StringOccurrence> {
        return stringOccurrences.entries
            .filter { predicate(it.key) }
            .flatMap { it.value }
    }

    fun findExactString(literal: String): List<StringOccurrence> {
        return stringOccurrences[literal] ?: emptyList()
    }

    fun findFieldAccesses(targetClass: String, fieldName: String): List<FieldAccess> {
        val normTarget = ClassHierarchy.normalizeType(targetClass)
        val key = "$normTarget#$fieldName"
        return fieldAccesses[key] ?: emptyList()
    }

    fun isComponentExported(className: String, attackSurface: AttackSurface): Boolean {
        val norm = ClassHierarchy.normalizeType(className)
        return attackSurface.components.any { it.name == norm && it.exported }
    }

    fun isReachableFromExportedComponent(
        callerClass: String,
        attackSurface: AttackSurface,
        maxHops: Int = 2
    ): Boolean {
        val normCaller = ClassHierarchy.normalizeType(callerClass)
        val exportedComponents = attackSurface.components
            .filter { it.exported }
            .map { it.name }
            .toSet()

        if (exportedComponents.contains(normCaller)) return true

        // Check 1-2 hop callers in call graph
        var currentCallers = setOf(normCaller)
        val visited = mutableSetOf(normCaller)

        for (hop in 1..maxHops) {
            val nextCallers = mutableSetOf<String>()
            for (curr in currentCallers) {
                val directCallers = callersByMethod[curr] ?: emptySet()
                for (caller in directCallers) {
                    if (exportedComponents.contains(caller)) return true
                    if (visited.add(caller)) {
                        nextCallers.add(caller)
                    }
                }
            }
            currentCallers = nextCallers
            if (currentCallers.isEmpty()) break
        }

        return false
    }

    companion object {
        fun build(archive: ApkArchive): DexIndex {
            val dexEntries = archive.listEntries().filter { entry ->
                entry.endsWith(".dex") && (entry.startsWith("classes") || entry.contains("/dex/classes") || entry == "classes.dex")
            }

            val classDefs = mutableMapOf<String, ClassDef>()
            val methods = mutableListOf<IndexedMethod>()
            val callSitesByTarget = mutableMapOf<String, MutableList<CallSite>>()
            val stringOccurrences = mutableMapOf<String, MutableList<StringOccurrence>>()
            val fieldAccesses = mutableMapOf<String, MutableList<FieldAccess>>()
            val callersByMethod = mutableMapOf<String, MutableSet<String>>()

            val opcodes = Opcodes.getDefault()

            for (entryName in dexEntries) {
                val bytes = archive.getEntryBytes(entryName) ?: continue
                val dexFile = try {
                    DexBackedDexFile(opcodes, bytes)
                } catch (e: Exception) {
                    continue
                }

                for (classDef in dexFile.classes) {
                    val normClass = ClassHierarchy.normalizeType(classDef.type)
                    classDefs[normClass] = classDef

                    val allMethods = classDef.methods
                    for (method in allMethods) {
                        val normMethod = IndexedMethod(
                            definingClass = normClass,
                            rawDefiningClass = classDef.type,
                            name = method.name,
                            returnType = method.returnType,
                            parameterTypes = method.parameterTypes.map { it.toString() },
                            accessFlags = method.accessFlags,
                            method = method,
                            dexName = entryName
                        )
                        methods.add(normMethod)

                        val impl = method.implementation ?: continue
                        var instIdx = 0

                        for (instruction in impl.instructions) {
                            if (instruction is ReferenceInstruction) {
                                when (val ref = instruction.reference) {
                                    is MethodReference -> {
                                        val targetClass = ClassHierarchy.normalizeType(ref.definingClass)
                                        val targetKey = "$targetClass#${ref.name}"
                                        val cs = CallSite(
                                            callerClass = normClass,
                                            callerMethod = method.name,
                                            callerMethodSig = "(${method.parameterTypes.joinToString("")})${method.returnType}",
                                            targetClass = targetClass,
                                            targetMethod = ref.name,
                                            targetSig = "(${ref.parameterTypes.joinToString("")})${ref.returnType}",
                                            instructionIndex = instIdx,
                                            instruction = instruction,
                                            dexName = entryName,
                                            method = method
                                        )
                                        callSitesByTarget.computeIfAbsent(targetKey) { mutableListOf() }.add(cs)
                                        callersByMethod.computeIfAbsent(targetClass) { mutableSetOf() }.add(normClass)
                                    }
                                    is StringReference -> {
                                        val str = ref.string
                                        val so = StringOccurrence(
                                            string = str,
                                            callerClass = normClass,
                                            callerMethod = method.name,
                                            instructionIndex = instIdx,
                                            dexName = entryName,
                                            method = method
                                        )
                                        stringOccurrences.computeIfAbsent(str) { mutableListOf() }.add(so)
                                    }
                                    is FieldReference -> {
                                        val targetClass = ClassHierarchy.normalizeType(ref.definingClass)
                                        val targetKey = "$targetClass#${ref.name}"
                                        val fa = FieldAccess(
                                            callerClass = normClass,
                                            callerMethod = method.name,
                                            targetClass = targetClass,
                                            fieldName = ref.name,
                                            fieldType = ref.type,
                                            instructionIndex = instIdx,
                                            instruction = instruction,
                                            dexName = entryName,
                                            method = method
                                        )
                                        fieldAccesses.computeIfAbsent(targetKey) { mutableListOf() }.add(fa)
                                    }
                                }
                            }
                            instIdx++
                        }
                    }
                }
            }

            val hierarchy = ClassHierarchy(classDefs)

            return DexIndex(
                classDefs = classDefs,
                methods = methods,
                hierarchy = hierarchy,
                callSitesByTarget = callSitesByTarget,
                stringOccurrences = stringOccurrences,
                fieldAccesses = fieldAccesses,
                callersByMethod = callersByMethod
            )
        }
    }
}
