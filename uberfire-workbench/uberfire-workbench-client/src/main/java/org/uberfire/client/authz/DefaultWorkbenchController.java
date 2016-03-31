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

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.jboss.errai.ioc.client.container.IOC;
import org.jboss.errai.security.shared.api.identity.User;
import org.uberfire.client.mvp.Activity;
import org.uberfire.client.mvp.PerspectiveActivity;
import org.uberfire.security.authz.AuthorizationManager;
import org.uberfire.security.authz.VotingStrategy;

@ApplicationScoped
public class DefaultWorkbenchController implements WorkbenchController {

    public static DefaultWorkbenchController get() {
        return IOC.getBeanManager().lookupBean(DefaultWorkbenchController.class).getInstance();
    }

    AuthorizationManager authorizationManager;
    User user;

    @Inject
    public DefaultWorkbenchController(AuthorizationManager authorizationManager, User user) {
        this.authorizationManager = authorizationManager;
        this.user = user;
    }

    @Override
    public ActivityCheck check(Activity activity) {
        return check(activity, null);
    }

    @Override
    public PerspectiveCheck check(PerspectiveActivity perspective) {
        return check(perspective, null);
    }

    @Override
    public ActivityCheck check(Activity activity, VotingStrategy votingStrategy) {
        return new ActivityCheck(authorizationManager, activity, user, votingStrategy);
    }

    @Override
    public PerspectiveCheck check(PerspectiveActivity perspective, VotingStrategy votingStrategy) {
        return new PerspectiveCheck(authorizationManager, perspective, user, votingStrategy);
    }
}