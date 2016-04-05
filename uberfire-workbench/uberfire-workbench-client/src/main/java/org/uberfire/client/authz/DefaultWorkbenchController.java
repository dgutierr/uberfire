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
import org.uberfire.client.mvp.PerspectiveActivity;
import org.uberfire.client.mvp.PopupActivity;
import org.uberfire.client.mvp.SplashScreenActivity;
import org.uberfire.client.mvp.WorkbenchEditorActivity;
import org.uberfire.client.mvp.WorkbenchScreenActivity;
import org.uberfire.security.authz.AuthorizationManager;
import org.uberfire.workbench.model.ActivityResourceType;

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
    public PerspectiveCheck perspectives() {
        return new PerspectiveCheck(authorizationManager, ActivityResourceType.PERSPECTIVE, user);
    }

    @Override
    public ActivityCheck screens() {
        return new PerspectiveCheck(authorizationManager, ActivityResourceType.SCREEN, user);
    }

    @Override
    public ActivityCheck popupScreens() {
        return new PerspectiveCheck(authorizationManager, ActivityResourceType.POPUP, user);
    }

    @Override
    public ActivityCheck splashScreens() {
        return new PerspectiveCheck(authorizationManager, ActivityResourceType.SPLASH, user);
    }

    @Override
    public ActivityCheck editors() {
        return new PerspectiveCheck(authorizationManager, ActivityResourceType.EDITOR, user);
    }

    @Override
    public PerspectiveCheck perspective(PerspectiveActivity perspective) {
        return new PerspectiveCheck(authorizationManager, perspective, user);
    }

    @Override
    public ActivityCheck screen(WorkbenchScreenActivity screen) {
        return new PerspectiveCheck(authorizationManager, screen, user);
    }

    @Override
    public ActivityCheck popupScreen(PopupActivity popup) {
        return new PerspectiveCheck(authorizationManager, popup, user);
    }

    @Override
    public ActivityCheck editor(WorkbenchEditorActivity editor) {
        return new PerspectiveCheck(authorizationManager, editor, user);
    }

    @Override
    public ActivityCheck splashScreen(SplashScreenActivity splash) {
        return new PerspectiveCheck(authorizationManager, splash, user);
    }
}