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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.jboss.errai.security.shared.api.Group;
import org.jboss.errai.security.shared.api.Role;
import org.jboss.errai.security.shared.api.identity.User;
import org.uberfire.security.Resource;
import org.uberfire.security.ResourceAction;
import org.uberfire.security.ResourceType;
import org.uberfire.security.authz.AuthorizationPolicy;
import org.uberfire.security.authz.AuthorizationResult;
import org.uberfire.security.authz.Permission;
import org.uberfire.security.authz.PermissionCollection;
import org.uberfire.security.authz.PermissionManager;
import org.uberfire.security.authz.PermissionType;
import org.uberfire.security.authz.PermissionTypeRegistry;
import org.uberfire.security.authz.VotingAlgorithm;
import org.uberfire.security.authz.VotingStrategy;

import static org.uberfire.security.authz.AuthorizationResult.*;

@ApplicationScoped
public class DefaultPermissionManager implements PermissionManager {

    private PermissionTypeRegistry permissionTypeRegistry;
    private AuthorizationPolicy authorizationPolicy;
    private DefaultAuthzResultCache cache;
    private VotingStrategy defaultVotingStrategy = VotingStrategy.PRIORITY;
    private Map<VotingStrategy,VotingAlgorithm> votingAlgorithmMap = new HashMap<>();

    public DefaultPermissionManager() {
        setVotingAlgorithm(VotingStrategy.AFFIRMATIVE, new AffirmativeBasedVoter());
        setVotingAlgorithm(VotingStrategy.CONSENSUS, new ConsensusBasedVoter());
        setVotingAlgorithm(VotingStrategy.UNANIMOUS, new UnanimousBasedVoter());
    }

    public DefaultPermissionManager(PermissionTypeRegistry permissionTypeRegistry, DefaultAuthzResultCache cache) {
        this();
        this.permissionTypeRegistry = permissionTypeRegistry;
        this.cache = cache;
    }

    @Inject
    public DefaultPermissionManager(PermissionTypeRegistry permissionTypeRegistry) {
        this(permissionTypeRegistry, new DefaultAuthzResultCache());
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
    public void setDefaultVotingStrategy(VotingStrategy votingStrategy) {
        defaultVotingStrategy = votingStrategy;
    }

    @Override
    public VotingStrategy getDefaultVotingStrategy() {
        return defaultVotingStrategy;
    }

    public VotingAlgorithm getVotingAlgorithm(VotingStrategy votingStrategy) {
        return votingAlgorithmMap.get(votingStrategy);
    }

    public void setVotingAlgorithm(VotingStrategy votingStrategy, VotingAlgorithm votingAlgorithm) {
        votingAlgorithmMap.put(votingStrategy, votingAlgorithm);
    }

    @Override
    public Permission createPermission(String name, boolean granted) {
        PermissionType permissionType = permissionTypeRegistry.resolve(name);
        return permissionType.createPermission(name, granted);
    }

    @Override
    public Permission createPermission(Resource resource, ResourceAction action, boolean granted) {

        // Does the resource have a type?

        // YES => check the resource action f.i: "project.read.myprojectid"
        if (resource.getResourceType() != null && !resource.getResourceType().equals(ResourceType.UNKNOWN)) {
            PermissionType permissionType = permissionTypeRegistry.resolve(resource.getResourceType().getName());
            return permissionType.createPermission(resource, action, granted);
        }
        // NO => just check the resource identifier
        return createPermission(resource.getIdentifier(), granted);
    }

    @Override
    public Permission createPermission(ResourceType resourceType, ResourceAction action, boolean granted) {
        PermissionType permissionType = permissionTypeRegistry.resolve(resourceType.getName());
        return permissionType.createPermission(resourceType, action, granted);
    }

    @Override
    public AuthorizationResult checkPermission(Permission permission, User user) {
        return checkPermission(permission, user, defaultVotingStrategy);
    }

    @Override
    public AuthorizationResult checkPermission(Permission permission, User user, VotingStrategy votingStrategy) {

        if (authorizationPolicy == null || permission == null) {
            return ACCESS_ABSTAIN;
        }
        AuthorizationResult result = cache.get(user, permission);
        if (result == null) {
            result = _checkPermission(permission, user, votingStrategy == null ? defaultVotingStrategy : votingStrategy);
            cache.put(user, permission, result);
        }
        return result;
    }

    protected AuthorizationResult _checkPermission(Permission permission, User user, VotingStrategy votingStrategy) {

        if (VotingStrategy.PRIORITY.equals(votingStrategy)) {
            PermissionCollection userPermissions = authorizationPolicy.getPermissions(user);
            return _checkPermission(permission, userPermissions);
        }
        else {
            List<AuthorizationResult> permList = _checkRoleAndGroupPermissions(permission, user);
            VotingAlgorithm votingAlgorithm = votingAlgorithmMap.get(votingStrategy);
            return votingAlgorithm.vote(permList);
        }
    }

    protected List<AuthorizationResult> _checkRoleAndGroupPermissions(Permission permission, User user) {
        List<AuthorizationResult> result = new ArrayList<>();
        if (user.getRoles() != null) {
            for (Role role : user.getRoles()) {
                PermissionCollection collection = authorizationPolicy.getPermissions(role);
                AuthorizationResult _partialResult = _checkPermission(permission, collection);
                result.add(_partialResult);
            }
        }
        if (user.getGroups() != null) {
            for (Group group : user.getGroups()) {
                PermissionCollection collection = authorizationPolicy.getPermissions(group);
                AuthorizationResult _partialResult = _checkPermission(permission, collection);
                result.add(_partialResult);
            }
        }
        return result;
    }

    protected AuthorizationResult _checkPermission(Permission permission, PermissionCollection collection) {
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
