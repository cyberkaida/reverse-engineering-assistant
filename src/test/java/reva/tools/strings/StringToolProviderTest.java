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
package reva.tools.strings;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;

/**
 * Unit tests for StringToolProvider
 */
public class StringToolProviderTest {
    @Mock
    private McpSyncServer mockServer;
    
    @Mock
    private Program mockProgram;
    
    @Mock
    private Listing mockListing;
    
    @Mock
    private DataIterator mockDataIterator;
    
    @Mock
    private Data mockData;
    
    @Mock
    private Address mockAddress;
    
    @Mock
    private DataType mockDataType;
    
    private StringToolProvider stringToolProvider;
    
    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        stringToolProvider = new StringToolProvider(mockServer);
    }
    
    @Test
    public void testConstructor() {
        assertNotNull("StringToolProvider should be created", stringToolProvider);
    }
    
    @Test
    public void testRegisterTools() throws McpError {
        // Test that registerTools completes without throwing
        stringToolProvider.registerTools();
    }
    
    @Test
    public void testGetStringInfoWithValidString() throws Exception {
        // Setup mock data
        String testString = "Hello, World!";
        byte[] testBytes = testString.getBytes();
        
        when(mockData.getValue()).thenReturn(testString);
        when(mockData.getAddress()).thenReturn(mockAddress);
        when(mockAddress.toString()).thenReturn("00401000");
        when(mockData.getBytes()).thenReturn(testBytes);
        when(mockData.getDataType()).thenReturn(mockDataType);
        when(mockDataType.getName()).thenReturn("string");
        when(mockData.getDefaultValueRepresentation()).thenReturn("\"Hello, World!\"");
        
        // Use reflection to test the private method
        java.lang.reflect.Method method = StringToolProvider.class.getDeclaredMethod("getStringInfo", Data.class);
        method.setAccessible(true);
        
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) method.invoke(stringToolProvider, mockData);
        
        assertNotNull("Result should not be null", result);
        assertEquals("Address should match", "0x00401000", result.get("address"));
        assertEquals("Content should match", testString, result.get("content"));
        assertEquals("Length should match", testString.length(), result.get("length"));
        assertEquals("Data type should match", "string", result.get("dataType"));
        assertEquals("Representation should match", "\"Hello, World!\"", result.get("representation"));
        assertNotNull("Hex bytes should be present", result.get("hexBytes"));
        assertEquals("Byte length should match", testBytes.length, result.get("byteLength"));
    }
    
    @Test
    public void testGetStringInfoWithNonString() throws Exception {
        // Setup mock data with non-string value
        when(mockData.getValue()).thenReturn(Integer.valueOf(42));
        
        // Use reflection to test the private method
        java.lang.reflect.Method method = StringToolProvider.class.getDeclaredMethod("getStringInfo", Data.class);
        method.setAccessible(true);
        
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) method.invoke(stringToolProvider, mockData);
        
        assertNull("Result should be null for non-string data", result);
    }
    
    @Test
    public void testInheritance() {
        // Test that StringToolProvider extends AbstractToolProvider
        assertTrue("StringToolProvider should extend AbstractToolProvider",
            reva.tools.AbstractToolProvider.class.isAssignableFrom(StringToolProvider.class));
    }
    
    @Test
    public void testToolProviderInterface() {
        // Test that StringToolProvider implements ToolProvider interface
        assertTrue("StringToolProvider should implement ToolProvider",
            reva.tools.ToolProvider.class.isAssignableFrom(StringToolProvider.class));
    }
}