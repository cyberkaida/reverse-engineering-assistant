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

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Fluent builder for the standard ReVa tool result envelope:
 * a {@code success} flag, the {@code programPath}, plus arbitrary data fields.
 * Insertion order is preserved (LinkedHashMap) for stable, readable JSON.
 *
 * <p>Available for providers that emit the standard success/programPath envelope;
 * existing providers have not yet been migrated to it (the schema migration was
 * schema-only) &mdash; prefer it for new tools and future result-envelope cleanups.
 */
public final class ToolResultBuilder {
    private final Map<String, Object> data = new LinkedHashMap<>();

    private ToolResultBuilder(String programPath) {
        data.put("success", Boolean.TRUE);
        if (programPath != null) {
            data.put("programPath", programPath);
        }
    }

    public static ToolResultBuilder create(String programPath) {
        return new ToolResultBuilder(programPath);
    }

    public ToolResultBuilder success(boolean success) {
        data.put("success", success);
        return this;
    }

    public ToolResultBuilder put(String key, Object value) {
        data.put(key, value);
        return this;
    }

    public ToolResultBuilder putAll(Map<String, Object> fields) {
        data.putAll(fields);
        return this;
    }

    /** @return the assembled result map for {@code createJsonResult(...)}. */
    public Map<String, Object> build() {
        return data;
    }
}
