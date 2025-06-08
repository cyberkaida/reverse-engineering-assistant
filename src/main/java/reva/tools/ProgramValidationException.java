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

/**
 * Exception thrown when program validation fails.
 * This exception is used to indicate various program-related errors such as:
 * - Program not found
 * - Program is in an invalid state (e.g., closed)
 * - Invalid program path provided
 */
public class ProgramValidationException extends RuntimeException {
    
    public ProgramValidationException(String message) {
        super(message);
    }
    
    public ProgramValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}