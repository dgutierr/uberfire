/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates.
 *  
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.uberfire.ext.security.management.client.screens.editor;

import javax.annotation.PostConstruct;
import javax.enterprise.context.Dependent;
import javax.enterprise.event.Event;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import com.google.gwt.safehtml.shared.SafeHtmlBuilder;
import com.google.gwt.user.client.ui.IsWidget;
import org.jboss.errai.security.shared.api.Role;
import org.uberfire.client.annotations.WorkbenchContextId;
import org.uberfire.client.annotations.WorkbenchPartTitle;
import org.uberfire.client.annotations.WorkbenchPartView;
import org.uberfire.client.annotations.WorkbenchScreen;
import org.uberfire.client.mvp.PlaceManager;
import org.uberfire.client.workbench.events.ChangeTitleWidgetEvent;
import org.uberfire.client.workbench.widgets.common.ErrorPopupPresenter;
import org.uberfire.ext.security.management.client.ClientUserSystemManager;
import org.uberfire.ext.security.management.client.resources.i18n.UsersManagementWorkbenchConstants;
import org.uberfire.ext.security.management.client.screens.BaseScreen;
import org.uberfire.ext.security.management.client.widgets.management.editor.role.workflow.RoleEditorWorkflow;
import org.uberfire.ext.security.management.client.widgets.management.events.ContextualEvent;
import org.uberfire.ext.security.management.client.widgets.management.events.OnEditEvent;
import org.uberfire.ext.security.management.client.widgets.management.events.OnShowEvent;
import org.uberfire.lifecycle.OnClose;
import org.uberfire.lifecycle.OnStartup;
import org.uberfire.mvp.PlaceRequest;

@Dependent
@WorkbenchScreen(identifier = RoleEditorScreen.SCREEN_ID )
public class RoleEditorScreen {

    public static final String SCREEN_ID = "RoleEditorScreen";
    public static final String ROLE_NAME = "roleName";

    @Inject
    PlaceManager placeManager;

    @Inject
    Event<ChangeTitleWidgetEvent> changeTitleNotification;

    @Inject
    ErrorPopupPresenter errorPopupPresenter;

    @Inject
    BaseScreen baseScreen;

    @Inject
    ClientUserSystemManager clientUserSystemManager;

    @Inject
    RoleEditorWorkflow roleEditorWorkflow;

    private String title = UsersManagementWorkbenchConstants.INSTANCE.roleEditor();
    private PlaceRequest placeRequest;
    String roleName;

    @PostConstruct
    public void init() {
    }

    @OnStartup
    public void onStartup(final PlaceRequest placeRequest) {
        this.placeRequest = placeRequest;
        final String roleName = placeRequest.getParameter(ROLE_NAME, null);
        show(roleName);
    }

    @OnClose
    public void onClose() {
        roleEditorWorkflow.clear();
        this.roleName = null;
    }

    void show(final String name) {
        baseScreen.init(roleEditorWorkflow);
        roleEditorWorkflow.show(name);
    }

    @WorkbenchPartTitle
    public String getTitle() {
        return title;
    }

    @WorkbenchPartView
    public IsWidget getWidget() {
        return baseScreen;
    }

    @WorkbenchContextId
    public String getMyContextRef() {
        return "roleEditorContext";
    }

    void onEditRoleEvent(@Observes final OnEditEvent onEditEvent) {
        if (checkEventContext(onEditEvent, roleEditorWorkflow.getRoleEditor())) {
            Role role = (Role) onEditEvent.getInstance();
            this.roleName = role.getName();
            changeTitleNotification.fire(new ChangeTitleWidgetEvent(placeRequest,
                    new SafeHtmlBuilder()
                            .appendEscaped(UsersManagementWorkbenchConstants.INSTANCE.editRole(roleName))
                            .toSafeHtml().asString()));
        }
    }

    void onShowRoleEvent(@Observes final OnShowEvent onShowEvent) {
        if (checkEventContext(onShowEvent, roleEditorWorkflow.getRoleEditor())) {
            Role role = (Role) onShowEvent.getInstance();
            this.roleName = role.getName();
            final String title = new SafeHtmlBuilder()
                    .appendEscaped(UsersManagementWorkbenchConstants.INSTANCE.showRole(roleName))
                    .toSafeHtml().asString();
            changeTitleNotification.fire(new ChangeTitleWidgetEvent(placeRequest, title));
        }
    }

    private boolean checkEventContext(final ContextualEvent contextualEvent, final Object context) {
        return contextualEvent != null && contextualEvent.getContext() != null && contextualEvent.getContext().equals(context);
    }
}
