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
import org.uberfire.client.mvp.PerspectiveActivity;
import org.uberfire.security.Resource;
import org.uberfire.security.authz.AuthorizationManager;
import org.uberfire.security.authz.AuthorizationCheck;
import org.uberfire.security.authz.VotingStrategy;

/**
 * A check executed over an {@link PerspectiveActivity} instance.
 */
public class PerspectiveCheck extends ActivityCheck {

    public PerspectiveCheck(AuthorizationManager authorizationManager, Resource resource, User user, VotingStrategy votingStrategy) {
        super(authorizationManager, resource, user, votingStrategy);
    }

    public AuthorizationCheck edit() {
        return super.check(PerspectiveAction.EDIT);
    }

    public AuthorizationCheck delete() {
        return super.check(PerspectiveAction.DELETE);
    }
}