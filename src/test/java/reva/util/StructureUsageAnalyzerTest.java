package reva.util;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit tests for StructureUsageAnalyzer utility class.
 */
public class StructureUsageAnalyzerTest {

    @Test
    public void testInferTypeFromSize() {
        StructureUsageAnalyzer.InferredType charType =
            StructureUsageAnalyzer.inferTypeFromSize(1, "test");
        assertEquals("char", charType.typeName);
        assertEquals(1, charType.size);

        StructureUsageAnalyzer.InferredType shortType =
            StructureUsageAnalyzer.inferTypeFromSize(2, "test");
        assertEquals("short", shortType.typeName);
        assertEquals(2, shortType.size);

        StructureUsageAnalyzer.InferredType intType =
            StructureUsageAnalyzer.inferTypeFromSize(4, "test");
        assertEquals("int", intType.typeName);
        assertEquals(4, intType.size);

        StructureUsageAnalyzer.InferredType longType =
            StructureUsageAnalyzer.inferTypeFromSize(8, "test");
        assertEquals("long", longType.typeName);
        assertEquals(8, longType.size);

        StructureUsageAnalyzer.InferredType unknownType =
            StructureUsageAnalyzer.inferTypeFromSize(3, "test");
        assertEquals("undefined", unknownType.typeName);
        assertEquals(3, unknownType.size);
    }

    @Test
    public void testMemoryAccessToMap() {
        StructureUsageAnalyzer.InferredType type =
            new StructureUsageAnalyzer.InferredType("int", 4, 0.8, "test evidence");

        StructureUsageAnalyzer.MemoryAccess access =
            new StructureUsageAnalyzer.MemoryAccess(
                0x10,
                StructureUsageAnalyzer.AccessType.READ,
                type,
                null,
                "testFunction",
                4
            );

        Map<String, Object> map = access.toMap();

        assertEquals("0x10", map.get("offset"));
        assertEquals(16L, map.get("offsetDecimal"));
        assertEquals("READ", map.get("accessType"));
        assertEquals(4, map.get("size"));
        assertEquals("testFunction", map.get("functionName"));
        assertNotNull(map.get("inferredType"));
    }

    @Test
    public void testInferredTypeToMap() {
        StructureUsageAnalyzer.InferredType type =
            new StructureUsageAnalyzer.InferredType("char*", 8, 0.75, "pointer deref");

        Map<String, Object> map = type.toMap();

        assertEquals("char*", map.get("typeName"));
        assertEquals(8, map.get("size"));
        assertEquals(0.75, (double) map.get("confidence"), 0.001);
        assertEquals("pointer deref", map.get("evidence"));
    }

    @Test
    public void testGenerateStructureDefinitionEmpty() {
        String result = StructureUsageAnalyzer.generateStructureDefinition(
            new ArrayList<>(), "EmptyStruct");

        assertTrue(result.contains("struct EmptyStruct"));
        assertTrue(result.contains("No accesses found"));
    }

    @Test
    public void testGenerateStructureDefinition() {
        List<StructureUsageAnalyzer.MemoryAccess> accesses = new ArrayList<>();

        accesses.add(new StructureUsageAnalyzer.MemoryAccess(
            0, StructureUsageAnalyzer.AccessType.READ,
            new StructureUsageAnalyzer.InferredType("int", 4, 0.8, "test"),
            null, "func", 4
        ));

        accesses.add(new StructureUsageAnalyzer.MemoryAccess(
            8, StructureUsageAnalyzer.AccessType.WRITE,
            new StructureUsageAnalyzer.InferredType("long", 8, 0.7, "test"),
            null, "func", 8
        ));

        String result = StructureUsageAnalyzer.generateStructureDefinition(accesses, "TestStruct");

        assertTrue(result.contains("struct TestStruct"));
        assertTrue(result.contains("field_00"));
        assertTrue(result.contains("field_08"));
        assertTrue(result.contains("padding")); // Should have padding between 4 and 8
    }

    @Test
    public void testAggregateAccessesByOffset() {
        List<StructureUsageAnalyzer.MemoryAccess> accesses = new ArrayList<>();

        // Add multiple accesses at same offset
        accesses.add(new StructureUsageAnalyzer.MemoryAccess(
            0x10, StructureUsageAnalyzer.AccessType.READ,
            new StructureUsageAnalyzer.InferredType("int", 4, 0.8, "test"),
            null, "func1", 4
        ));

        accesses.add(new StructureUsageAnalyzer.MemoryAccess(
            0x10, StructureUsageAnalyzer.AccessType.WRITE,
            new StructureUsageAnalyzer.InferredType("int", 4, 0.8, "test"),
            null, "func2", 4
        ));

        accesses.add(new StructureUsageAnalyzer.MemoryAccess(
            0x20, StructureUsageAnalyzer.AccessType.READ,
            new StructureUsageAnalyzer.InferredType("char", 1, 0.6, "test"),
            null, "func1", 1
        ));

        Map<Long, Map<String, Object>> aggregated =
            StructureUsageAnalyzer.aggregateAccessesByOffset(accesses);

        assertEquals(2, aggregated.size());

        Map<String, Object> offset10 = aggregated.get(0x10L);
        assertNotNull(offset10);
        assertEquals(1, offset10.get("readCount"));
        assertEquals(1, offset10.get("writeCount"));

        Map<String, Object> offset20 = aggregated.get(0x20L);
        assertNotNull(offset20);
        assertEquals(1, offset20.get("readCount"));
        assertEquals(0, offset20.get("writeCount"));
    }

    @Test
    public void testAnalyzeMemoryAccessesWithNull() {
        // Should return empty list, not throw
        List<StructureUsageAnalyzer.MemoryAccess> result =
            StructureUsageAnalyzer.analyzeMemoryAccesses(null, null);
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }
}
