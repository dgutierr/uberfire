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
package org.uberfire.backend.server.authz;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.uberfire.backend.authz.AuthorizationPolicyStorage;
import org.uberfire.commons.services.cdi.Startup;
import org.uberfire.security.authz.AuthorizationPolicy;
import org.uberfire.security.authz.PermissionManager;
import org.uberfire.security.impl.authz.AuthorizationPolicyBuilder;

/**
 * An Uberfire's startup bean that scans the classpath looking for an authorization policy to deploy (a file named
 * <i>security-policy.properties</i>).</p>
 *
 * <p>If located, the policy file is loaded and passed along the {@link AuthorizationPolicyStorage}. The deployment
 * process is only executed once, so if a policy instance has been already stored then the deployment is left out.
 * The {@link AuthorizationPolicyMarshaller} class is used to read and convert the entries defined at
 * the <i>security-policy.properties</i> file into an {@link AuthorizationPolicy} instance.</p>
 *
 * <p>It is also possible to split the policy file into multiple property files. The
 * <i>security-policy.properties</i> file is always mandatory as it serves as a marker file. Alongside that file,
 * several <i>security-module-?.properties</i> files can be created. The split mechanism allows either for the
 * provision of just a single full standalone policy file or multiple module files each of them containing different
 * entries. The way those files are defined is always up to the application developer.</p>
 */
@Startup
@ApplicationScoped
public class AuthorizationPolicyDeployer {

    private Logger logger = LoggerFactory.getLogger(AuthorizationPolicyDeployer.class);

    private AuthorizationPolicyStorage authzPolicyStorage;
    private PermissionManager permissionManager;

    public AuthorizationPolicyDeployer() {
    }

    @Inject
    public AuthorizationPolicyDeployer(AuthorizationPolicyStorage authzPolicyStorage, PermissionManager permissionManager) {
        this.authzPolicyStorage = authzPolicyStorage;
        this.permissionManager = permissionManager;
    }

    @PostConstruct
    public void deployPolicy() {
        AuthorizationPolicy policy = authzPolicyStorage.loadPolicy();
        if (policy == null) {
            policy = loadPolicy();
            if (policy == null) {
                logger.info("Security policy not defined");
            } else {
                authzPolicyStorage.savePolicy(policy);
                logger.info("Security policy deployed");
            }
        } else {
            logger.info("Security policy active");
        }
    }

    public AuthorizationPolicy loadPolicy() {
        URL fileURL = Thread.currentThread().getContextClassLoader().getResource("security-policy.properties");
        if (fileURL != null) {
            Path path = Paths.get(URI.create("file://" + fileURL.getPath())).getParent();
            return loadPolicy(path);
        } else {
            return null;
        }
    }

    public AuthorizationPolicy loadPolicy(Path policyDir) {
        AuthorizationPolicyBuilder builder = permissionManager.newAuthorizationPolicy();
        AuthorizationPolicyMarshaller marshaller = new AuthorizationPolicyMarshaller();
        if (policyDir != null) {
            try {
                Files.list(policyDir)
                        .filter(this::isPolicyFile)
                        .forEach(p -> loadPolicyFile(builder, marshaller, p));
            } catch (IOException e) {
                logger.warn("Error loading security policy files", e);
            }
        }
        return builder.build();
    }

    public boolean isPolicyFile(Path p) {
        String fileName = p.getName(p.getNameCount()-1).toString();
        return fileName.equals("security-policy.properties") || fileName.startsWith("security-module-");
    }

    public void loadPolicyFile(AuthorizationPolicyBuilder builder, AuthorizationPolicyMarshaller marshaller, Path path) {
        try (BufferedReader reader = Files.newBufferedReader(path)) {
            Properties p = new Properties();
            p.load(reader);
            marshaller.read(builder, p);
        }
        catch (IOException e) {
            logger.error("Security policy load error", e);
        }
    }
}
