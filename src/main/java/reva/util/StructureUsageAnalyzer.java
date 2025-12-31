/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Utility class for analyzing structure usage patterns in decompiled code.
 * Used by infer-structure-from-usage and validate-structure-against-usage tools.
 */
public class StructureUsageAnalyzer {

    /**
     * Access type enumeration.
     */
    public enum AccessType {
        READ,
        WRITE,
        READ_WRITE,
        UNKNOWN
    }

    /**
     * Represents a memory access at a specific offset.
     */
    public static class MemoryAccess {
        public final long offset;
        public final AccessType type;
        public final InferredType inferredType;
        public final Address location;
        public final String functionName;
        public final int size;

        public MemoryAccess(long offset, AccessType type, InferredType inferredType,
                Address location, String functionName, int size) {
            this.offset = offset;
            this.type = type;
            this.inferredType = inferredType;
            this.location = location;
            this.functionName = functionName;
            this.size = size;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("offset", String.format("0x%02X", offset));
            map.put("offsetDecimal", offset);
            map.put("accessType", type.toString());
            map.put("size", size);
            if (location != null) {
                map.put("location", AddressUtil.formatAddress(location));
            }
            if (functionName != null) {
                map.put("functionName", functionName);
            }
            if (inferredType != null) {
                map.put("inferredType", inferredType.toMap());
            }
            return map;
        }
    }

    /**
     * Represents an inferred type from usage analysis.
     */
    public static class InferredType {
        public final String typeName;
        public final int size;
        public final double confidence;
        public final String evidence;

        public InferredType(String typeName, int size, double confidence, String evidence) {
            this.typeName = typeName;
            this.size = size;
            this.confidence = confidence;
            this.evidence = evidence;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("typeName", typeName);
            map.put("size", size);
            map.put("confidence", confidence);
            map.put("evidence", evidence);
            return map;
        }
    }

    /**
     * Analyze memory accesses for a high variable in a decompiled function.
     *
     * @param hf The high function from decompilation
     * @param targetVar The high variable to analyze
     * @return List of memory accesses found
     */
    public static List<MemoryAccess> analyzeMemoryAccesses(HighFunction hf, HighVariable targetVar) {
        List<MemoryAccess> accesses = new ArrayList<>();
        if (hf == null || targetVar == null) {
            return accesses;
        }

        String functionName = hf.getFunction().getName();

        // Get all instances (varnodes) of this variable
        Varnode[] instances = targetVar.getInstances();
        if (instances == null) {
            return accesses;
        }

        Set<Long> seenOffsets = new HashSet<>();

        for (Varnode instance : instances) {
            // Look at uses of this varnode
            Iterator<PcodeOp> descendants = instance.getDescendants();
            while (descendants.hasNext()) {
                PcodeOp op = descendants.next();
                Optional<MemoryAccess> access = analyzeOperation(op, instance, functionName, seenOffsets);
                if (access.isPresent()) {
                    accesses.add(access.get());
                }
            }
        }

        return accesses;
    }

    /**
     * Analyze a single pcode operation for offset access patterns.
     */
    private static Optional<MemoryAccess> analyzeOperation(PcodeOp op, Varnode baseVar,
            String functionName, Set<Long> seenOffsets) {
        if (op == null) {
            return Optional.empty();
        }

        int opcode = op.getOpcode();

        // Handle PTRADD - pointer + offset
        if (opcode == PcodeOp.PTRADD) {
            return analyzePtrAdd(op, functionName, seenOffsets);
        }

        // Handle PTRSUB - pointer - offset (for negative offsets)
        if (opcode == PcodeOp.PTRSUB) {
            return analyzePtrSub(op, functionName, seenOffsets);
        }

        // Handle INT_ADD used as pointer arithmetic
        if (opcode == PcodeOp.INT_ADD) {
            return analyzeIntAdd(op, functionName, seenOffsets);
        }

        // Handle LOAD operations
        if (opcode == PcodeOp.LOAD) {
            return analyzeLoad(op, baseVar, functionName, seenOffsets);
        }

        // Handle STORE operations
        if (opcode == PcodeOp.STORE) {
            return analyzeStore(op, baseVar, functionName, seenOffsets);
        }

        return Optional.empty();
    }

    private static Optional<MemoryAccess> analyzePtrAdd(PcodeOp op, String functionName,
            Set<Long> seenOffsets) {
        Varnode[] inputs = op.getInputs();
        if (inputs.length < 3) {
            return Optional.empty();
        }

        // PTRADD: base, index, element_size
        Varnode indexVar = inputs[1];
        Varnode sizeVar = inputs[2];

        if (indexVar.isConstant() && sizeVar.isConstant()) {
            long index = indexVar.getOffset();
            long elemSize = sizeVar.getOffset();
            long offset = index * elemSize;

            if (seenOffsets.contains(offset)) {
                return Optional.empty();
            }
            seenOffsets.add(offset);

            InferredType type = inferTypeFromSize((int) elemSize, "PTRADD element size");
            Address loc = op.getSeqnum() != null ? op.getSeqnum().getTarget() : null;

            return Optional.of(new MemoryAccess(offset, AccessType.READ, type, loc,
                    functionName, (int) elemSize));
        }

        return Optional.empty();
    }

    private static Optional<MemoryAccess> analyzePtrSub(PcodeOp op, String functionName,
            Set<Long> seenOffsets) {
        Varnode[] inputs = op.getInputs();
        if (inputs.length < 2) {
            return Optional.empty();
        }

        Varnode offsetVar = inputs[1];
        if (offsetVar.isConstant()) {
            long offset = offsetVar.getOffset();

            if (seenOffsets.contains(offset)) {
                return Optional.empty();
            }
            seenOffsets.add(offset);

            InferredType type = new InferredType("undefined", 1, 0.3, "PTRSUB offset");
            Address loc = op.getSeqnum() != null ? op.getSeqnum().getTarget() : null;

            return Optional.of(new MemoryAccess(offset, AccessType.READ, type, loc,
                    functionName, 1));
        }

        return Optional.empty();
    }

    private static Optional<MemoryAccess> analyzeIntAdd(PcodeOp op, String functionName,
            Set<Long> seenOffsets) {
        Varnode[] inputs = op.getInputs();
        if (inputs.length < 2) {
            return Optional.empty();
        }

        // Look for constant offset
        for (Varnode input : inputs) {
            if (input.isConstant()) {
                long offset = input.getOffset();

                // Filter out obviously non-offset values
                if (offset < 0 || offset > 0x10000) {
                    continue;
                }

                if (seenOffsets.contains(offset)) {
                    return Optional.empty();
                }
                seenOffsets.add(offset);

                InferredType type = new InferredType("undefined", 1, 0.2, "INT_ADD offset");
                Address loc = op.getSeqnum() != null ? op.getSeqnum().getTarget() : null;

                return Optional.of(new MemoryAccess(offset, AccessType.READ, type, loc,
                        functionName, 1));
            }
        }

        return Optional.empty();
    }

    private static Optional<MemoryAccess> analyzeLoad(PcodeOp op, Varnode baseVar,
            String functionName, Set<Long> seenOffsets) {
        Varnode output = op.getOutput();
        if (output == null) {
            return Optional.empty();
        }

        // Check if this load is from our base variable
        Varnode[] inputs = op.getInputs();
        if (inputs.length < 2) {
            return Optional.empty();
        }

        Varnode addrVar = inputs[1];
        int size = output.getSize();

        // Try to extract offset from address computation
        PcodeOp defOp = addrVar.getDef();
        if (defOp != null) {
            Optional<Long> offset = extractOffsetFromDef(defOp);
            if (offset.isPresent()) {
                long off = offset.get();
                if (seenOffsets.contains(off)) {
                    return Optional.empty();
                }
                seenOffsets.add(off);

                InferredType type = inferTypeFromSize(size, "LOAD operation");
                Address loc = op.getSeqnum() != null ? op.getSeqnum().getTarget() : null;

                return Optional.of(new MemoryAccess(off, AccessType.READ, type, loc,
                        functionName, size));
            }
        }

        return Optional.empty();
    }

    private static Optional<MemoryAccess> analyzeStore(PcodeOp op, Varnode baseVar,
            String functionName, Set<Long> seenOffsets) {
        Varnode[] inputs = op.getInputs();
        if (inputs.length < 3) {
            return Optional.empty();
        }

        Varnode addrVar = inputs[1];
        Varnode valueVar = inputs[2];
        int size = valueVar.getSize();

        // Try to extract offset from address computation
        PcodeOp defOp = addrVar.getDef();
        if (defOp != null) {
            Optional<Long> offset = extractOffsetFromDef(defOp);
            if (offset.isPresent()) {
                long off = offset.get();
                if (seenOffsets.contains(off)) {
                    return Optional.empty();
                }
                seenOffsets.add(off);

                InferredType type = inferTypeFromSize(size, "STORE operation");
                Address loc = op.getSeqnum() != null ? op.getSeqnum().getTarget() : null;

                return Optional.of(new MemoryAccess(off, AccessType.WRITE, type, loc,
                        functionName, size));
            }
        }

        return Optional.empty();
    }

    /**
     * Extract constant offset from a pcode definition.
     */
    public static Optional<Long> extractOffsetFromDef(PcodeOp defOp) {
        if (defOp == null) {
            return Optional.empty();
        }

        int opcode = defOp.getOpcode();

        if (opcode == PcodeOp.PTRADD) {
            Varnode[] inputs = defOp.getInputs();
            if (inputs.length >= 3 && inputs[1].isConstant() && inputs[2].isConstant()) {
                long index = inputs[1].getOffset();
                long elemSize = inputs[2].getOffset();
                return Optional.of(index * elemSize);
            }
        }

        if (opcode == PcodeOp.PTRSUB) {
            Varnode[] inputs = defOp.getInputs();
            if (inputs.length >= 2 && inputs[1].isConstant()) {
                return Optional.of(inputs[1].getOffset());
            }
        }

        if (opcode == PcodeOp.INT_ADD) {
            Varnode[] inputs = defOp.getInputs();
            for (Varnode input : inputs) {
                if (input.isConstant()) {
                    long offset = input.getOffset();
                    if (offset >= 0 && offset <= 0x10000) {
                        return Optional.of(offset);
                    }
                }
            }
        }

        if (opcode == PcodeOp.COPY) {
            Varnode input = defOp.getInput(0);
            if (input != null) {
                return extractOffsetFromDef(input.getDef());
            }
        }

        return Optional.empty();
    }

    /**
     * Infer type from access size.
     */
    public static InferredType inferTypeFromSize(int size, String evidence) {
        switch (size) {
            case 1:
                return new InferredType("char", 1, 0.6, evidence);
            case 2:
                return new InferredType("short", 2, 0.6, evidence);
            case 4:
                return new InferredType("int", 4, 0.6, evidence);
            case 8:
                return new InferredType("long", 8, 0.6, evidence);
            default:
                return new InferredType("undefined", size, 0.3, evidence);
        }
    }

    /**
     * Find all functions that reference a given structure type.
     *
     * @param program The program to search
     * @param structure The structure data type to find
     * @return List of functions using the structure
     */
    public static List<Function> findReferencingFunctions(Program program, DataType structure) {
        List<Function> result = new ArrayList<>();
        if (program == null || structure == null) {
            return result;
        }

        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (functionUsesType(func, structure)) {
                result.add(func);
            }
        }

        return result;
    }

    /**
     * Check if a function uses a specific data type.
     */
    public static boolean functionUsesType(Function func, DataType dataType) {
        if (func == null || dataType == null) {
            return false;
        }

        // Check return type
        if (isTypeOrPointerToType(func.getReturnType(), dataType)) {
            return true;
        }

        // Check parameters
        for (Parameter param : func.getParameters()) {
            if (isTypeOrPointerToType(param.getDataType(), dataType)) {
                return true;
            }
        }

        // Check local variables
        for (Variable var : func.getAllVariables()) {
            if (isTypeOrPointerToType(var.getDataType(), dataType)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a type is equivalent to or a pointer to another type.
     */
    private static boolean isTypeOrPointerToType(DataType check, DataType target) {
        if (check == null || target == null) {
            return false;
        }

        // Direct equivalence
        if (check.isEquivalent(target)) {
            return true;
        }

        // Check if it's a pointer to the target
        if (check instanceof Pointer) {
            DataType pointedTo = ((Pointer) check).getDataType();
            if (pointedTo != null && pointedTo.isEquivalent(target)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Find a high variable by name in a high function.
     *
     * @param hf The high function to search
     * @param name The variable name to find
     * @return The high variable, or null if not found
     */
    public static HighVariable findVariableByName(HighFunction hf, String name) {
        if (hf == null || name == null) {
            return null;
        }

        Iterator<HighSymbol> symbols = hf.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            if (name.equals(symbol.getName())) {
                return symbol.getHighVariable();
            }
        }

        return null;
    }

    /**
     * Find a high variable by parameter index in a high function.
     *
     * @param hf The high function to search
     * @param paramIndex 0-based parameter index
     * @return The high variable, or null if not found
     */
    public static HighVariable findParameterByIndex(HighFunction hf, int paramIndex) {
        if (hf == null || paramIndex < 0) {
            return null;
        }

        Iterator<HighSymbol> symbols = hf.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            if (symbol.isParameter()) {
                int idx = symbol.getCategoryIndex();
                if (idx == paramIndex) {
                    return symbol.getHighVariable();
                }
            }
        }

        return null;
    }

    /**
     * Generate a C structure definition from analyzed memory accesses.
     *
     * @param accesses List of memory accesses
     * @param structName Name for the generated structure
     * @return C structure definition string
     */
    public static String generateStructureDefinition(List<MemoryAccess> accesses, String structName) {
        if (accesses == null || accesses.isEmpty()) {
            return "// No accesses found\nstruct " + structName + " {\n};\n";
        }

        // Sort accesses by offset
        accesses.sort((a, b) -> Long.compare(a.offset, b.offset));

        StringBuilder sb = new StringBuilder();
        sb.append("struct ").append(structName).append(" {\n");

        long currentOffset = 0;

        for (MemoryAccess access : accesses) {
            // Add padding if needed
            if (access.offset > currentOffset) {
                long padding = access.offset - currentOffset;
                sb.append(String.format("    undefined field_%02X[%d]; // padding\n",
                        currentOffset, padding));
                currentOffset = access.offset;
            }

            // Add the field
            String typeName = access.inferredType != null ? access.inferredType.typeName : "undefined";
            int size = access.size > 0 ? access.size : 1;

            sb.append(String.format("    %s field_%02X; // offset 0x%02X, size %d, %s\n",
                    typeName, access.offset, access.offset, size, access.type));

            currentOffset = access.offset + size;
        }

        sb.append("};\n");
        sb.append("// Total analyzed size: ").append(currentOffset).append(" bytes\n");

        return sb.toString();
    }

    /**
     * Aggregate memory accesses by offset for summary statistics.
     *
     * @param accesses List of memory accesses
     * @return Map of offset to access count and type info
     */
    public static Map<Long, Map<String, Object>> aggregateAccessesByOffset(List<MemoryAccess> accesses) {
        Map<Long, Map<String, Object>> result = new HashMap<>();

        for (MemoryAccess access : accesses) {
            Map<String, Object> offsetInfo = result.computeIfAbsent(access.offset, k -> {
                Map<String, Object> info = new HashMap<>();
                info.put("offset", String.format("0x%02X", k));
                info.put("readCount", 0);
                info.put("writeCount", 0);
                info.put("size", access.size);
                info.put("inferredType", access.inferredType != null ?
                        access.inferredType.typeName : "unknown");
                return info;
            });

            if (access.type == AccessType.READ || access.type == AccessType.READ_WRITE) {
                offsetInfo.put("readCount", (int) offsetInfo.get("readCount") + 1);
            }
            if (access.type == AccessType.WRITE || access.type == AccessType.READ_WRITE) {
                offsetInfo.put("writeCount", (int) offsetInfo.get("writeCount") + 1);
            }
        }

        return result;
    }
}
