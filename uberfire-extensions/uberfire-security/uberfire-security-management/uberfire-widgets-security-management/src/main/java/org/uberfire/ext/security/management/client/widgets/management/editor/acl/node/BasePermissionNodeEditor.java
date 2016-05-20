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

import org.uberfire.ext.security.management.client.widgets.management.editor.acl.ACLEditor;

public abstract class BasePermissionNodeEditor implements PermissionNodeEditor {

    protected ACLEditor aclEditor = null;
    protected int width = 300;
    protected int leftMargin = 0;
    protected int treeLevel = 0;
    protected int padding = 15;

    @Override
    public ACLEditor getACLEditor() {
        return aclEditor;
    }

    @Override
    public void setACLEditor(ACLEditor aclEditor) {
        this.aclEditor = aclEditor;
    }

    @Override
    public int getTreeLevel() {
        return treeLevel;
    }

    @Override
    public void setTreeLevel(int treeLevel) {
        this.treeLevel = treeLevel;
    }

    @Override
    public int getNodePanelWidth() {
        return width - leftMargin - (treeLevel*padding);
    }

    @Override
    public void setLeftMargin(int margin) {
        this.leftMargin = margin;
    }
}
