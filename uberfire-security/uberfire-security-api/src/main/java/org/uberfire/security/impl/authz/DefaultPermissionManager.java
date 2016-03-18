/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates.
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

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.jboss.errai.security.shared.api.identity.User;
import org.uberfire.security.Resource;
import org.uberfire.security.ResourceAction;
import org.uberfire.security.authz.AuthorizationPolicy;
import org.uberfire.security.authz.AuthorizationResult;
import org.uberfire.security.authz.Permission;
import org.uberfire.security.authz.PermissionCollection;
import org.uberfire.security.authz.PermissionManager;
import org.uberfire.security.authz.PermissionType;
import org.uberfire.security.authz.PermissionTypeRegistry;

import static org.uberfire.security.authz.AuthorizationResult.*;

@ApplicationScoped
public class DefaultPermissionManager implements PermissionManager {

    private PermissionTypeRegistry permissionTypeRegistry;
    private AuthorizationPolicy authorizationPolicy;
    private DefaultAuthzResultCache cache;

    public DefaultPermissionManager() {
    }

    @Inject
    public DefaultPermissionManager(PermissionTypeRegistry permissionTypeRegistry) {
        this.permissionTypeRegistry = permissionTypeRegistry;
        this.cache = new DefaultAuthzResultCache();
    }

    public DefaultPermissionManager(PermissionTypeRegistry permissionTypeRegistry, DefaultAuthzResultCache cache) {
        this.permissionTypeRegistry = permissionTypeRegistry;
        this.cache = cache;
    }

    public AuthorizationPolicy getAuthorizationPolicy() {
        return authorizationPolicy;
    }

    public void setAuthorizationPolicy(AuthorizationPolicy authorizationPolicy) {
        this.authorizationPolicy = authorizationPolicy;
        this.cache.clear();
    }

    @Override
    public AuthorizationPolicyBuilder newAuthorizationPolicy() {
        return new AuthorizationPolicyBuilder(permissionTypeRegistry);
    }

    @Override
    public Permission createPermission(String name, boolean granted) {
        PermissionType permissionType = permissionTypeRegistry.resolve(name);
        return permissionType.createPermission(name, granted);
    }

    @Override
    public Permission createPermission(Resource resource, ResourceAction action, boolean granted) {

        // Does the resource have a type?

        // YES => check the resource action f.i: "project.view.myprojectid"
        if (resource.getType() != null) {
            PermissionType permissionType = permissionTypeRegistry.resolve(resource.getType().getName());
            return permissionType.createPermission(resource, action, granted);
        }
        // NO => just check the resource identifier
        return createPermission(resource.getIdentifier(), granted);
    }

    @Override
    public AuthorizationResult checkPermission(Permission permission, User user) {

        if (authorizationPolicy == null || permission == null) {
            return ACCESS_ABSTAIN;
        }
        AuthorizationResult result = cache.get(user, permission);
        if (result == null) {
            PermissionCollection userPermissions = authorizationPolicy.getPermissions(user);
            result = checkPermission(permission, userPermissions);
            cache.put(user, permission, result);
        }
        return result;
    }

    protected AuthorizationResult checkPermission(Permission permission, PermissionCollection collection) {
        if (collection == null) {
            return ACCESS_ABSTAIN;
        }
        Permission existing = collection.get(permission.getName());
        if (existing != null) {
            return existing.getResult().equals(permission.getResult()) ? ACCESS_GRANTED : ACCESS_DENIED;
        }
        if (collection.implies(permission)) {
            return ACCESS_GRANTED;
        }
        Permission inverted = permission.clone();
        inverted.setResult(inverted.getResult().invert());
        if (collection.implies(inverted)) {
            return ACCESS_DENIED;
        }
        return ACCESS_ABSTAIN;
    }
}
