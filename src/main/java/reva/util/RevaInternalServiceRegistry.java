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

import java.util.HashMap;
import java.util.Map;

/**
 * A simple service registry to allow components to locate each other at runtime.
 * This is a static registry that provides global access to core services.
 */
public class RevaInternalServiceRegistry {
    private static final Map<Class<?>, Object> services = new HashMap<>();

    /**
     * Register a service implementation
     * @param <T> The service type
     * @param serviceClass The service interface class
     * @param implementation The service implementation
     */
    public static <T> void registerService(Class<T> serviceClass, T implementation) {
        services.put(serviceClass, implementation);
    }

    /**
     * Get a registered service
     * @param <T> The service type
     * @param serviceClass The service interface class
     * @return The service implementation or null if not found
     */
    @SuppressWarnings("unchecked")
    public static <T> T getService(Class<T> serviceClass) {
        return (T) services.get(serviceClass);
    }

    /**
     * Remove a service from the registry
     * @param <T> The service type
     * @param serviceClass The service interface class
     */
    public static <T> void unregisterService(Class<T> serviceClass) {
        services.remove(serviceClass);
    }

    /**
     * Clear all registered services
     */
    public static void clearAllServices() {
        services.clear();
    }
}
