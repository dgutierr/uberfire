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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.jboss.errai.ioc.client.container.SyncBeanDef;
import org.jboss.errai.ioc.client.container.SyncBeanManager;
import org.uberfire.client.mvp.AbstractWorkbenchPerspectiveActivity;
import org.uberfire.client.mvp.PerspectiveActivity;
import org.uberfire.client.resources.i18n.PermissionTreeI18n;
import org.uberfire.security.Resource;
import org.uberfire.security.ResourceAction;
import org.uberfire.security.authz.Permission;
import org.uberfire.security.authz.PermissionManager;
import org.uberfire.security.client.authz.tree.LoadCallback;
import org.uberfire.security.client.authz.tree.LoadOptions;
import org.uberfire.security.client.authz.tree.PermissionNode;
import org.uberfire.security.client.authz.tree.PermissionTreeProvider;
import org.uberfire.security.client.authz.tree.impl.PermissionLeafNode;
import org.uberfire.security.client.authz.tree.impl.PermissionResourceNode;
import org.uberfire.workbench.model.ActivityResourceType;

import static org.uberfire.client.authz.PerspectiveAction.*;

@ApplicationScoped
public class PerspectiveTreeProvider implements PermissionTreeProvider {

    private SyncBeanManager iocManager;
    private PermissionManager permissionManager;
    private PermissionTreeI18n i18n;
    private boolean active = true;
    private String resourceName = null;
    private String rootNodeName = null;
    private int rootNodePosition = 0;

    public PerspectiveTreeProvider() {
    }

    @Inject
    public PerspectiveTreeProvider(SyncBeanManager iocManager, PermissionManager permissionManager, PermissionTreeI18n i18n) {
        this.iocManager = iocManager;
        this.permissionManager = permissionManager;
        this.i18n = i18n;
        this.resourceName = i18n.perspectiveResourceName();
        this.rootNodeName = i18n.perspectivesNodeName();
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public String getResourceName() {
        return resourceName;
    }

    public void setResourceName(String resourceName) {
        this.resourceName = resourceName;
    }

    public String getRootNodeName() {
        return rootNodeName;
    }

    public void setRootNodeName(String rootNodeName) {
        this.rootNodeName = rootNodeName;
    }

    public int getRootNodePosition() {
        return rootNodePosition;
    }

    public void setRootNodePosition(int rootNodePosition) {
        this.rootNodePosition = rootNodePosition;
    }

    @Override
    public PermissionNode buildRootNode() {
        PermissionResourceNode rootNode = new PermissionResourceNode(resourceName, this);
        rootNode.setNodeName(rootNodeName);
        rootNode.setPositionInTree(rootNodePosition);
        rootNode.addPermission(newPermission(READ), i18n.perspectiveRead());
        rootNode.addPermission(newPermission(DELETE), i18n.perspectiveDelete());
        rootNode.addPermission(newPermission(EDIT), i18n.perspectiveEdit());
        rootNode.addPermission(newPermission(CREATE), i18n.perspectiveCreate());
        return rootNode;
    }

    @Override
    public void loadChildren(PermissionNode parent, LoadOptions options, LoadCallback callback) {
        if (parent.getNodeName().equals(rootNodeName)) {
            callback.afterLoad(buildPerspectiveNodes(options));
        }
    }

    private Permission newPermission(ResourceAction action) {
        return permissionManager.createPermission(ActivityResourceType.PERSPECTIVE, action, true);
    }

    private Permission newPermission(Resource resource, ResourceAction action) {
        return permissionManager.createPermission(resource, action, true);
    }

    private List<PermissionNode> buildPerspectiveNodes(LoadOptions options) {

        List<PermissionNode> nodes = new ArrayList<>();
        for (SyncBeanDef<PerspectiveActivity> beanDef : iocManager.lookupBeans(PerspectiveActivity.class)) {
            PerspectiveActivity p = beanDef.getInstance();
            if (match(p, options)) {
                nodes.add(toPerspectiveNode(p));
            }
        }

        int max = options.getMaxNodes();
        return max > 0 && max < nodes.size() ? nodes.subList(0, max) : nodes;
    }

    private PermissionNode toPerspectiveNode(PerspectiveActivity p) {
        String fullName = p.getIdentifier();
        int lastDot = fullName.lastIndexOf(".");
        String name = lastDot != -1 ? fullName.substring(lastDot+1) : fullName;

        PermissionLeafNode node = new PermissionLeafNode();
        node.setNodeName(name);
        node.setNodeFullName(fullName);
        node.addPermission(newPermission(p, READ), i18n.perspectiveRead());

        // Only runtime created perspectives can be modified
        if (!(p instanceof AbstractWorkbenchPerspectiveActivity)) {
            node.addPermission(newPermission(p, DELETE), i18n.perspectiveDelete());
            node.addPermission(newPermission(p, EDIT), i18n.perspectiveEdit());
        }
        return node;
    }

    private boolean match(Resource r, LoadOptions options) {
        Collection<String> includedIds = options.getResourceIdsIncluded();
        Collection<String> excludedIds = options.getResourceIdsExcluded();

        if (excludedIds != null && !excludedIds.isEmpty()) {
            for (String resourceId : excludedIds) {
                if (r.getIdentifier().contains(resourceId)) {
                    return false;
                }
            }
        }
        if (includedIds == null || includedIds.isEmpty()) {
            return false;
        }
        for (String resourceId : includedIds) {
            if (r.getIdentifier().toLowerCase().contains(resourceId.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
}