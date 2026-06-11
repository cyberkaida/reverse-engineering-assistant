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

import java.io.IOException;

import ghidra.framework.data.DefaultCheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Persist a Program the strongest way its DomainFile allows: save locally, then checkin
 *  when under version control. Shared by analyze (background job) and checkin-program. */
public final class ProgramPersistenceUtil {

    public enum PersistMode { AUTO, SAVE, NONE }
    public enum PersistAction { CHECKIN, ADD_TO_VC, SAVE, SKIP }

    public static final class PersistResult {
        public final PersistAction action;   // strongest step that SUCCEEDED
        public final boolean saved;
        public final String error;            // checkin-step error after successful save, or null
        PersistResult(PersistAction action, boolean saved, String error) {
            this.action = action; this.saved = saved; this.error = error;
        }
    }

    private ProgramPersistenceUtil() {}

    /** Decide what {@link #persist} would do — pure, unit-testable. */
    public static PersistAction selectAction(DomainFile file, PersistMode mode) {
        if (mode == PersistMode.NONE || file == null || file.isReadOnly()) {
            return PersistAction.SKIP;
        }
        if (mode == PersistMode.SAVE) {
            return PersistAction.SAVE;
        }
        if (file.canCheckin()) {
            return PersistAction.CHECKIN;
        }
        // canCheckin() requires modifiedSinceCheckout(), which only counts SAVED
        // changes: a checked-out file whose modifications are still in memory
        // reports canCheckin()=false until a save bumps the local version. persist()
        // saves before the checkin step, so plan CHECKIN for that case too.
        if (file.isVersioned() && file.isCheckedOut() && file.isChanged()) {
            return PersistAction.CHECKIN;
        }
        if (file.canAddToRepository()) {
            return PersistAction.ADD_TO_VC;
        }
        return PersistAction.SAVE;
    }

    /** Save the program, then checkin/addToVC when AUTO and the file is versioned.
     *  Save runs first and is reported even if a subsequent checkin fails. Caller must
     *  ensure NO transaction is open and run this OFF the Swing thread. */
    public static PersistResult persist(Program program, PersistMode mode, String message,
            boolean keepCheckedOut, TaskMonitor monitor) throws IOException, CancelledException {
        DomainFile file = program.getDomainFile();
        PersistAction planned = selectAction(file, mode);
        if (planned == PersistAction.SKIP) {
            return new PersistResult(PersistAction.SKIP, false, null);
        }

        program.save(message, monitor);   // always save first → local durability
        program.flushEvents();             // ensure the SAVED event is processed

        if (planned == PersistAction.SAVE) {
            return new PersistResult(PersistAction.SAVE, true, null);
        }

        try {
            if (planned == PersistAction.CHECKIN) {
                DefaultCheckinHandler handler =
                    new DefaultCheckinHandler(message + "\n💜🐉✨ (ReVa)", keepCheckedOut, false);
                file.checkin(handler, monitor);
                return new PersistResult(PersistAction.CHECKIN, true, null);
            } else { // ADD_TO_VC
                file.addToVersionControl(message, !keepCheckedOut, monitor);
                return new PersistResult(PersistAction.ADD_TO_VC, true, null);
            }
        } catch (Exception e) {
            // Keep the successful local save; report the checkin failure.
            return new PersistResult(PersistAction.SAVE, true,
                "checkin failed after save: " + e.getMessage());
        }
    }
}
