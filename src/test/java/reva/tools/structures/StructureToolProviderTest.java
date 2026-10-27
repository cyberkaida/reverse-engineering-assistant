package reva.tools.structures;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import reva.RevaHeadlessIntegrationTestBase;
import reva.util.TypeArchives;

public class StructureToolProviderTest extends RevaHeadlessIntegrationTestBase {

    @Test
    public void windowsTypesParseAgainstArchives() throws Exception {
        CParser parser = new CParser(program.getDataTypeManager(), false, TypeArchives.forProgram(program));
        DataType dt = parser.parse("struct s { HANDLE h; DWORD n; };");
        assertTrue(dt instanceof Structure);
        assertEquals(2, ((Structure) dt).getNumComponents());
    }

    @Test
    public void providerParserFactoryUsesArchives() throws Exception {
        CParser parser = StructureToolProvider.newParser(program);
        DataType dt = parser.parse("struct t { HANDLE h; size_t n; };");
        assertEquals(2, ((Structure) dt).getNumComponents());
    }
}
