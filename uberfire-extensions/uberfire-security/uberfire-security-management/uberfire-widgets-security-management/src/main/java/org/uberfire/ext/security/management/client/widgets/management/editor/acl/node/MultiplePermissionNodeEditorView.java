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

import javax.enterprise.context.Dependent;
import javax.inject.Inject;

import com.google.gwt.dom.client.Document;
import com.google.gwt.dom.client.Style;
import com.google.gwt.event.dom.client.ClickEvent;
import com.google.gwt.user.client.ui.Composite;
import com.google.gwt.user.client.ui.FlowPanel;
import com.google.gwt.user.client.ui.IsWidget;
import org.gwtbootstrap3.client.ui.Icon;
import org.gwtbootstrap3.client.ui.constants.IconType;
import org.jboss.errai.common.client.dom.Anchor;
import org.jboss.errai.common.client.dom.Div;
import org.jboss.errai.ui.shared.api.annotations.DataField;
import org.jboss.errai.ui.shared.api.annotations.EventHandler;
import org.jboss.errai.ui.shared.api.annotations.Templated;
import org.uberfire.ext.security.management.client.resources.i18n.SecurityManagementConstants;

@Dependent
@Templated
public class MultiplePermissionNodeEditorView extends Composite
        implements MultiplePermissionNodeEditor.View {

    private MultiplePermissionNodeEditor presenter;

    @Inject
    @DataField
    Anchor nodeAnchor;

    @Inject
    @DataField
    Div nodeAnchorPanel;

    @Inject
    @DataField
    FlowPanel nodePermissions;

    @Inject
    @DataField
    Div collapsePanel;

    @Inject
    @DataField
    FlowPanel nodeChildren;

    @Inject
    @DataField
    Anchor addChildAnchor;

    @Inject
    @DataField
    Anchor clearChildrenAnchor;

    @Inject
    @DataField
    Div addChildPanel;

    @Inject
    @DataField
    Div clearChildrenPanel;

    @Inject
    @DataField
    Anchor cancelAnchor;

    @Inject
    @DataField
    FlowPanel childSelectorPanel;

    @Override
    public void init(MultiplePermissionNodeEditor presenter) {
        this.presenter = presenter;

        String collapseId = Document.get().createUniqueId();
        collapsePanel.setId(collapseId);
        nodeAnchor.setHref("#" + collapseId);
        clearChildrenAnchor.setTextContent(" " + SecurityManagementConstants.INSTANCE.clearChildren());
    }

    @Override
    public void setNodeName(String name) {
        nodeAnchor.setTextContent(name);
    }

    @Override
    public void setNodePanelWidth(int width) {
        nodeAnchorPanel.getStyle().setProperty("width", width + "px");
    }

    @Override
    public void setNodeFullName(String name) {
        nodeAnchor.setTitle(name);
    }

    @Override
    public void setResourceName(String name) {
        String addText = SecurityManagementConstants.INSTANCE.addPermissionToResource(name);
        addChildAnchor.setTextContent(" " + addText);
    }

    @Override
    public void addPermission(PermissionSwitch permissionSwitch) {
        nodePermissions.add(permissionSwitch);
    }

    @Override
    public void addChildEditor(PermissionNodeEditor editor, boolean dynamic) {
        if (dynamic) {
            editor.setLeftMargin(20);

            FlowPanel panel = new FlowPanel();
            org.gwtbootstrap3.client.ui.Anchor anchor = new org.gwtbootstrap3.client.ui.Anchor();
            anchor.add(new Icon(IconType.REMOVE));
            anchor.getElement().getStyle().setWidth(20, Style.Unit.PX);
            anchor.getElement().getStyle().setDisplay(Style.Display.TABLE_CELL);
            anchor.addClickHandler(event -> presenter.onRemoveChild(editor));
            editor.asWidget().getElement().getStyle().setDisplay(Style.Display.TABLE_CELL);
            panel.add(anchor);
            panel.add(editor);
            nodeChildren.add(panel);
        }
        else {
            nodeChildren.add(editor);
        }
    }

    @Override
    public void clearChildren() {
        nodeChildren.clear();
    }

    @Override
    public String getChildSelectorHint(String resourceName) {
        return SecurityManagementConstants.INSTANCE.selectResourceInstance(resourceName);
    }

    @Override
    public String getChildSearchHint(String resourceName) {
        return SecurityManagementConstants.INSTANCE.searchResourceInstance(resourceName);
    }

    @Override
    public String getChildrenNotFoundMsg(String resourceName) {
        return SecurityManagementConstants.INSTANCE.resourceInstanceNotFound(resourceName);
    }

    @Override
    public void setChildSelector(IsWidget childSelector) {
        childSelectorPanel.clear();
        childSelectorPanel.add(childSelector);
    }

    @Override
    public void showChildSelector() {
        addChildPanel.getStyle().removeProperty("display");
    }

    @Override
    public void hideChildSelector() {
        addChildPanel.getStyle().setProperty("display", "none");
    }

    @Override
    public void setAddChildEnabled(boolean enabled) {
        if (enabled) {
            addChildAnchor.getStyle().removeProperty("display");
        } else {
            addChildAnchor.getStyle().setProperty("display", "none");
        }
    }

    @Override
    public void setClearChildrenEnabled(boolean enabled) {
        if (enabled) {
            clearChildrenAnchor.getStyle().removeProperty("display");
        } else {
            clearChildrenAnchor.getStyle().setProperty("display", "none");
        }
    }

    @EventHandler("nodeAnchor")
    private void onNodeClick(ClickEvent event) {
        presenter.onNodeClick();
    }

    @EventHandler("addChildAnchor")
    private void onAddChild(ClickEvent event) {
        presenter.onAddChildStart();
    }

    @EventHandler("clearChildrenAnchor")
    private void onClearChildren(ClickEvent event) {
        presenter.onClearChildren();
    }

    @EventHandler("cancelAnchor")
    private void onCancelAdd(ClickEvent event) {
        presenter.onAddChildCancel();
    }
}
