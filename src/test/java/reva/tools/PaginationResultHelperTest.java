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
package reva.tools;

import static org.junit.Assert.assertEquals;

import java.util.List;
import java.util.Map;

import org.junit.Test;

/**
 * Unit test for {@link AbstractToolProvider#paginationResult}. No Ghidra
 * environment required. The helper is {@code protected static}; because this
 * test lives in the same package ({@code reva.tools}) it can reference the
 * member directly without subclassing.
 */
public class PaginationResultHelperTest {

    @Test
    public void testEnvelopeFields() {
        AbstractToolProvider.PaginationParams params =
            new AbstractToolProvider.PaginationParams(0, 50);
        Map<String, Object> out =
            AbstractToolProvider.paginationResult(params, "symbols", List.of("a", "b"), 2);

        assertEquals(Integer.valueOf(0), out.get("startIndex"));
        assertEquals(Integer.valueOf(50), out.get("requestedCount"));
        assertEquals(Integer.valueOf(2), out.get("actualCount"));
        assertEquals(Integer.valueOf(2), out.get("nextStartIndex")); // startIndex + actualCount
        assertEquals(Integer.valueOf(2), out.get("totalProcessed"));
        assertEquals(List.of("a", "b"), out.get("symbols"));
    }

    @Test
    public void testNonZeroStartIndexAdvancesNext() {
        AbstractToolProvider.PaginationParams params =
            new AbstractToolProvider.PaginationParams(10, 25);
        Map<String, Object> out =
            AbstractToolProvider.paginationResult(params, "items", List.of("x", "y", "z"), 7);

        assertEquals(Integer.valueOf(10), out.get("startIndex"));
        assertEquals(Integer.valueOf(25), out.get("requestedCount"));
        assertEquals(Integer.valueOf(3), out.get("actualCount"));
        assertEquals(Integer.valueOf(13), out.get("nextStartIndex")); // 10 + 3
        assertEquals(Integer.valueOf(7), out.get("totalProcessed"));
        assertEquals(List.of("x", "y", "z"), out.get("items"));
    }
}
