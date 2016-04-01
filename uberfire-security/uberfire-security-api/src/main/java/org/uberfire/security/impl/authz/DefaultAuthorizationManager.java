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

import java.util.List;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.jboss.errai.security.shared.api.identity.User;
import org.uberfire.security.Resource;
import org.uberfire.security.ResourceAction;
import org.uberfire.security.ResourceType;
import org.uberfire.security.authz.AuthorizationManager;
import org.uberfire.security.authz.AuthorizationResult;
import org.uberfire.security.authz.AuthorizationCheck;
import org.uberfire.security.authz.Permission;
import org.uberfire.security.authz.PermissionManager;
import org.uberfire.security.authz.VotingStrategy;

import static org.uberfire.commons.validation.PortablePreconditions.*;

@ApplicationScoped
public class DefaultAuthorizationManager implements AuthorizationManager {

    private PermissionManager permissionManager;

    public DefaultAuthorizationManager() {
    }

    @Inject
    public DefaultAuthorizationManager(PermissionManager permissionManager) {
        this.permissionManager = permissionManager;
    }

    public boolean authorize(Resource resource, User user) {
        return authorize(resource, null, user, null);
    }

    @Override
    public boolean authorize(Resource resource, ResourceAction action, User user) {
        return authorize(resource, action, user, null);
    }

    @Override
    public boolean authorize(ResourceType resourceType, ResourceAction action, User user) {
        return authorize(resourceType, action, user, null);
    }

    @Override
    public boolean authorize(Resource resource, User user, VotingStrategy votingStrategy) {
        return authorize(resource, null, user, votingStrategy);
    }

    @Override
    public boolean authorize(Resource resource, ResourceAction action, User user, VotingStrategy votingStrategy) {
        checkNotNull("resource", resource);
        checkNotNull("subject", user);

        // A resource may depend on others
        List<Resource> deps = resource.getDependencies();
        if (deps != null) {

            // One dep is accessible
            for (Resource dep : deps) {
                boolean itemAccess = authorize(dep, action, user);
                if (itemAccess) {
                    return true;
                }
            }
            // No deps found or all deps denied
            return false;
        }
        // Unknown resource with no deps
        String id = resource.getIdentifier();
        if (id == null || id.length() == 0) {
            return true;
        }

        // Ask the permission manager about the given action
        Permission p = permissionManager.createPermission(resource, action, true);
        return authorize(p, user, votingStrategy);
    }

    @Override
    public boolean authorize(ResourceType resourceType, ResourceAction action, User user, VotingStrategy votingStrategy) {
        // Ask the permission manager about the given action
        Permission p = permissionManager.createPermission(resourceType, action, true);
        return authorize(p, user, votingStrategy);
    }

    @Override
    public boolean authorize(String permission, User user) {
        return authorize(permission, user, null);
    }

    @Override
    public boolean authorize(Permission permission, User user) {
        return authorize(permission, user, null);
    }

    @Override
    public boolean authorize(String permission, User user, VotingStrategy votingStrategy) {
        Permission p = permissionManager.createPermission(permission, true);
        return authorize(p, user, votingStrategy);
    }

    @Override
    public boolean authorize(Permission permission, User user, VotingStrategy votingStrategy) {

        // If granted or abstain the return true. Reasons to abstain:
        // - no security policy defined
        // - no explicit permissions assigned
        AuthorizationResult result = permissionManager.checkPermission(permission, user, votingStrategy);
        return !AuthorizationResult.ACCESS_DENIED.equals(result);
    }

    @Override
    public AuthorizationCheck check(Resource target, User user) {
        return check(target, user, null);
    }

    @Override
    public AuthorizationCheck check(Resource target, User user, VotingStrategy votingStrategy) {
        return new ResourceCheck(this, target, user, votingStrategy);
    }

    @Override
    public AuthorizationCheck check(String permission, User user) {
        return check(permission, user, null);
    }

    @Override
    public AuthorizationCheck check(String permission, User user, VotingStrategy votingStrategy) {
        return new PermissionCheck(permissionManager, permission, user, votingStrategy);
    }
}
