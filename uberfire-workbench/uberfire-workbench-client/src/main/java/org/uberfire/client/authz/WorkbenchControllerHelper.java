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
 *   check(perspective1).delete()
 *     .denied(() -> deleteButton.setVisible(false))
 * }</pre>

 */
public class WorkbenchControllerHelper {

    /**
     * See {@link WorkbenchController#check(Activity)}
     */
    public static ActivityCheck check(Activity activity) {
        return DefaultWorkbenchController.get().check(activity);
    }

    /**
     * See {@link WorkbenchController#check(PerspectiveActivity)}
     */
    public static PerspectiveCheck check(PerspectiveActivity perspective) {
        return DefaultWorkbenchController.get().check(perspective);
    }
}