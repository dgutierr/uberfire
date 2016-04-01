/*
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.uberfire.client.authz;

import org.uberfire.client.mvp.Activity;
import org.uberfire.client.mvp.PerspectiveActivity;
import org.uberfire.security.authz.VotingStrategy;

/**
 * A helper class providing static method access to the {@link WorkbenchController} underlying instance.
 *
 * <p>Example usage:</p>
 * <pre>
 * {@code import static org.uberfire.client.authz.WorkbenchControllerHelper.*;
 *
 *   Button deleteButton;
 *   PerspectiveActivity perspective1;
 *
 *   perspective(perspective1).delete()
 *     .denied(() -> deleteButton.setVisible(false))
 * }</pre>

 */
public class WorkbenchControllerHelper {

    /**
     * See {@link WorkbenchController#perspective(PerspectiveActivity)}
     */
    public static PerspectiveCheck perspectives() {
        return DefaultWorkbenchController.get().perspectives();
    }

    /**
     * See {@link WorkbenchController#perspective(PerspectiveActivity)}
     */
    public static PerspectiveCheck perspective(PerspectiveActivity perspective) {
        return DefaultWorkbenchController.get().perspective(perspective);
    }

    /**
     * See {@link WorkbenchController#activity(Activity)}
     */
    public static ActivityCheck activity(Activity activity) {
        return DefaultWorkbenchController.get().activity(activity);
    }
}