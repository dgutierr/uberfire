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

package org.uberfire.security.impl.authz;

import org.jboss.errai.security.shared.api.identity.User;
import org.uberfire.mvp.Command;
import org.uberfire.security.Resource;
import org.uberfire.security.ResourceAction;
import org.uberfire.security.authz.AuthorizationManager;
import org.uberfire.security.authz.AuthorizationCheck;

/**
 * A check executed over a {@link Resource} instance.
 */
public class ResourceCheck implements AuthorizationCheck {

    protected AuthorizationManager authorizationManager;
    protected Resource resource;
    protected User user;
    protected Boolean result = null;

    public ResourceCheck(AuthorizationManager authorizationManager, Resource resource, User user) {
        this.authorizationManager = authorizationManager;
        this.resource = resource;
        this.user = user;
    }

    protected ResourceCheck check(ResourceAction action) {
        result = authorizationManager.authorize(resource, action, user);
        return this;
    }

    @Override
    public AuthorizationCheck granted(Command onGranted) {
        if (result()) {
            onGranted.execute();
        }
        return this;
    }

    @Override
    public AuthorizationCheck denied(Command onDenied) {
        if (!result()) {
            onDenied.execute();
        }
        return this;
    }

    @Override
    public boolean result() {
        if (result == null) {
            check(ResourceAction.VIEW);
        }
        return result;
    }
}