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

import org.jboss.errai.security.shared.api.identity.User;
import org.uberfire.client.mvp.Activity;
import org.uberfire.client.mvp.PerspectiveActivity;
import org.uberfire.security.authz.PermissionManager;
import org.uberfire.security.authz.VotingStrategy;

/**
 * An interface for checking access to workbench resources (perspectives, screens, editors, ...)
 * using a fluent styled API.
 *
 * <p>Example usage:</p>
 * <pre>
 * {@code Button deleteButton;
 *   WorkbenchController workbenchController;
 *   PerspectiveActivity perspective1;
 *
 *   workbenchController.perspective(perspective1).delete()
 *     .granted(() -> deleteButton.setEnabled(true))
 *     .denied(() -> deleteButton.setEnabled(false))
 * }</pre>
 */
public interface WorkbenchController {

    /**
     * Creates a brand new instance for checking access to any {@link Activity} instance.
     *
     * @param activity The Activity instance
     *
     * @return A handler for dealing with activity the check API.
     */
    ActivityCheck activity(Activity activity);

    /**
     * Creates a brand new instance for checking global perspective actions actions.
     *
     * @return A handler for dealing with the perspective check API.
     */
    PerspectiveCheck perspectives();

    /**
     * Creates a brand new instance for checking actions over {@link PerspectiveActivity} instances.
     *
     * @param perspective The PerspectiveActivity instance
     *
     * @return A handler for dealing with the perspective check API.
     */
    PerspectiveCheck perspective(PerspectiveActivity perspective);
}