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

package org.uberfire.ext.security.management.client.widgets.management.editor.acl.node;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.annotation.PostConstruct;
import javax.enterprise.context.Dependent;
import javax.enterprise.event.Event;
import javax.inject.Inject;

import com.google.gwt.user.client.ui.IsWidget;
import com.google.gwt.user.client.ui.Widget;
import org.uberfire.client.mvp.UberView;
import org.uberfire.ext.security.management.client.widgets.management.events.PermissionChangedEvent;
import org.uberfire.ext.security.management.client.widgets.management.events.PermissionNodeAddedEvent;
import org.uberfire.ext.security.management.client.widgets.management.events.PermissionNodeRemovedEvent;
import org.uberfire.ext.widgets.common.client.dropdown.LiveSearchDropDown;
import org.uberfire.ext.widgets.common.client.dropdown.LiveSearchService;
import org.uberfire.security.authz.AuthorizationResult;
import org.uberfire.security.authz.Permission;
import org.uberfire.security.client.authz.tree.HasResources;
import org.uberfire.security.client.authz.tree.LoadOptions;
import org.uberfire.security.client.authz.tree.PermissionNode;
import org.uberfire.security.client.authz.tree.PermissionTreeProvider;
import org.uberfire.security.client.authz.tree.impl.DefaultLoadOptions;
import org.uberfire.security.client.authz.tree.impl.PermissionResourceNode;

@Dependent
public class MultiplePermissionNodeEditor extends BasePermissionNodeEditor {

    public interface View extends UberView<MultiplePermissionNodeEditor> {

        void setNodeName(String name);

        void setNodePanelWidth(int width);

        void setNodeFullName(String name);

        void setResourceName(String name);

        void addPermission(PermissionSwitch permissionSwitch);

        void addChildEditor(PermissionNodeEditor editor, boolean dynamic);

        void clearChildren();

        String getChildSelectorHint(String resourceName);

        String getChildSearchHint(String resourceName);

        String getChildrenNotFoundMsg(String resourceName);

        void setChildSelector(IsWidget childSelector);

        void showChildSelector();

        void hideChildSelector();

        void setAddChildEnabled(boolean enabled);

        void setClearChildrenEnabled(boolean enabled);
    }

    View view;
    PermissionWidgetFactory widgetFactory;
    LiveSearchDropDown liveSearchDropDown;
    Event<PermissionChangedEvent> permissionChangedEvent;
    Event<PermissionNodeAddedEvent> permissionNodeAddedEvent;
    Event<PermissionNodeRemovedEvent> permissionNodeRemovedEvent;
    PermissionNode permissionNode;
    List<PermissionNodeEditor> childEditorList;
    Map<String,PermissionNode> childSelectorNodeMap = new TreeMap<>();

    @Inject
    public MultiplePermissionNodeEditor(View view,
                                        LiveSearchDropDown liveSearchDropDown,
                                        PermissionWidgetFactory widgetFactory,
                                        Event<PermissionChangedEvent> permissionChangedEvent,
                                        Event<PermissionNodeAddedEvent> permissionNodeAddedEvent,
                                        Event<PermissionNodeRemovedEvent> permissionNodeRemovedEvent) {
        this.view = view;
        this.liveSearchDropDown = liveSearchDropDown;
        this.widgetFactory = widgetFactory;
        this.permissionChangedEvent = permissionChangedEvent;
        this.permissionNodeAddedEvent = permissionNodeAddedEvent;
        this.permissionNodeRemovedEvent = permissionNodeRemovedEvent;
    }

    @PostConstruct
    public void init() {
        view.init(this);
    }

    @Override
    public Widget asWidget() {
        return view.asWidget();
    }

    public boolean hasResources() {
        return permissionNode instanceof HasResources;
    }

    @Override
    public PermissionNode getPermissionNode() {
        return permissionNode;
    }

    @Override
    public List<PermissionNodeEditor> getChildren() {
        return childEditorList;
    }

    @Override
    public void edit(PermissionNode node) {
        permissionNode = node;
        String name = node.getNodeName();
        String fullName = node.getNodeFullName();

        view.setNodeName(name);
        view.setNodePanelWidth(getNodePanelWidth());
        view.setClearChildrenEnabled(false);
        if (fullName != null && !fullName.equals(name)) {
            view.setNodeFullName(fullName);
        }

        // Resources are only supported for dynamic nodes
        if (hasResources()) {
            String resourceName = ((PermissionResourceNode) permissionNode).getResourceName();
            liveSearchDropDown.setSelectorHint(view.getChildSelectorHint(resourceName));
            liveSearchDropDown.setSearchHint(view.getChildSearchHint(resourceName));
            liveSearchDropDown.setNotFoundMessage(view.getChildrenNotFoundMsg(resourceName));
            liveSearchDropDown.setMaxItems(10);
            liveSearchDropDown.setWidth(220);
            liveSearchDropDown.setSearchService(childrenSearchService);
            liveSearchDropDown.setOnChange(() -> onChildSelected(liveSearchDropDown.getSelectedItem()));

            view.setAddChildEnabled(true);
            view.setResourceName(resourceName);
            view.setChildSelector(liveSearchDropDown);
        }

        // Init the switch control for every permission
        for (Permission permission : permissionNode.getPermissionList()) {
            String grantName = permissionNode.getPermissionGrantName(permission);
            String denyName = permissionNode.getPermissionDenyName(permission);
            boolean granted = AuthorizationResult.ACCESS_GRANTED.equals(permission.getResult());

            PermissionSwitch permissionSwitch = widgetFactory.createSwitch();
            permissionSwitch.init(grantName, denyName, granted, () -> {
                permission.setResult(permissionSwitch.isOn() ? AuthorizationResult.ACCESS_GRANTED : AuthorizationResult.ACCESS_DENIED);
                permissionChangedEvent.fire(new PermissionChangedEvent(getACLEditor(), permission, permissionSwitch.isOn()));
            });
            view.addPermission(permissionSwitch);
        }
    }

    public void expand() {
        if (childEditorList == null) {
            doExpand();
        }
    }

    public void collapse() {
        permissionNode.collapse();
    }

    protected void doExpand() {
        childEditorList = new ArrayList<>();
        permissionNode.expand(children -> {
            for (PermissionNode child : children) {
                registerChild(child);
            }
        });
    }

    protected void registerChild(PermissionNode child) {
        PermissionNodeEditor nodeEditor = widgetFactory.createEditor(child);
        nodeEditor.setACLEditor(this.getACLEditor());
        nodeEditor.setTreeLevel(getTreeLevel()+1);
        childEditorList.add(nodeEditor);
        view.addChildEditor(nodeEditor, hasResources());
        view.setClearChildrenEnabled(hasResources());
        nodeEditor.edit(child);
    }

    // View events

    public void onNodeClick() {
        if (permissionNode.isExpanded()) {
            collapse();
        } else {
            expand();
        }
    }

    public void onAddChildStart() {
        view.showChildSelector();
    }

    public void onAddChildCancel() {
        view.hideChildSelector();

    }

    public void onClearChildren() {
        for (PermissionNodeEditor child : new ArrayList<>(childEditorList)) {
            onRemoveChild(child);
        }
    }

    public void onRemoveChild(PermissionNodeEditor child) {
        if (childEditorList != null) {
            childEditorList.remove(child);
            view.setClearChildrenEnabled(hasResources() && !childEditorList.isEmpty());
        }

        liveSearchDropDown.clear();
        view.hideChildSelector();
        view.clearChildren();
        for (PermissionNodeEditor nodeEditor : childEditorList) {
            view.addChildEditor(nodeEditor, hasResources());
        }

        permissionNodeRemovedEvent.fire(new PermissionNodeRemovedEvent(getACLEditor(), permissionNode, child.getPermissionNode()));
    }

    public void onChildSelected(String childName) {
        PermissionNode childNode = childSelectorNodeMap.remove(childName);
        overwritePermissions(permissionNode, childNode);
        registerChild(childNode);
        view.hideChildSelector();
        liveSearchDropDown.clear();

        permissionNodeAddedEvent.fire(new PermissionNodeAddedEvent(getACLEditor(), permissionNode, childNode));
    }

    protected void overwritePermissions(PermissionNode parent, PermissionNode child) {
        for (Permission p1 : parent.getPermissionList()) {
            for (Permission p2 : child.getPermissionList()) {
                if (p1.impliesName(p2)) {
                    p2.setResult(p1.getResult().invert());
                }
            }
        }
    }

    LiveSearchService childrenSearchService = (pattern, maxResults, callback) -> {

        PermissionTreeProvider provider = permissionNode.getPermissionTreeProvider();
        LoadOptions loadOptions = new DefaultLoadOptions(Collections.singleton(pattern), null, maxResults);

        provider.loadChildren(permissionNode, loadOptions, children -> {

            childSelectorNodeMap.clear();

            for (PermissionNode childNode : children) {
                String childName = childNode.getNodeName();
                if (!childAlreadyAdded(childName)) {
                    childSelectorNodeMap.put(childName, childNode);
                }
            }
            List<String> result = new ArrayList<>(childSelectorNodeMap.keySet());
            callback.afterSearch(result);
        });
    };

    protected boolean childAlreadyAdded(String nodeName) {
        for (PermissionNodeEditor childEditor : childEditorList) {
            String existingName = childEditor.getPermissionNode().getNodeName();
            if (existingName.equals(nodeName)) {
                return true;
            }
        }
        return false;
    }
}
