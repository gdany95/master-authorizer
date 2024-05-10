Master Authorizer is the main authorization server used by the Linic microservices. The purpose of this microservice is to provide multitenancy support, authorization based on roles within the Tenant and multi login based on different email addresses. Each section is described in detail below.

# Multitenancy

This service adds the notion of a Tenant to authorization. A user has configurable roles for each Tenant, as well as global roles which applies to all tenants. The resource servers are responsible for getting the list of roles the logged user has within the selected tenant using the endpoint provided by this service.

# Multi login

A user can login using multiple IDP's, as well as using different email addresses. This is possible because we map the external user id to our internal `MultiUser`, which can have multiple external id's mapped to a user. Because of this feature, we don't really care what the email address of the user is in the authorization process, so don't expect an email as the principal name.

# Authentication

The purpose of this service is not to authenticate, thus authentication should be delegated. This is done using OAuth2 or OIDC. You just register providers and you can login using, for example, your Google, Github, Facebook.. account. If you would, however, like to keep authentication in-house, you can spin up a Keycloak server and delegate authentication to it.

The authentication providers are used only for identity purposes. The only property this service requires from a delegated IDP is the principal name. It is not concerned with other claims or properties returned by the providers. The principal name is usually the internal id of the user in the provider's system, not the email address, so don't count on taking the email address from the principal's name.

Multi login for a user is implemented by the possibility of adding multiple principal names to a user, thus different internal id's from multiple IDP's will be mapped to the same user in our system.

**NOTE: ** There is a password field in our `MultiUser` entity, but it's only there for legacy purposes. Only form login is implemented for it; no other functionality like registering or password recovery is implemented, so you should delegate authentication.

# Authorization

Authorization is role-based. Each `MultiUser` can have multiple roles within a Tenant as well as roles within multiple Tenants. There are also roles that do not belong to any Tenant, called global roles. The global roles are mainly used for system administration purposes. Each role has a set of regular Spring Authorities, which are the actual permissions a user has.

# Getting started

Prerequisites:
- Postgres. This service uses the `jsonb` data format, native to Postgres, for storing JSON, thus an embedded H2 database will not work.
- Dependencies: ro.linic.util:commons(these are added as Maven dependencies, but are not on Maven Central, so you will need to import the projects in your workspace and run `mvn install` to install them in your local maven repo)

Installation:
1. Configure the Postgres datasource connection in application.yml
2. Configure your OAuth2 providers in application.yml(eg.: spring.security.oauth2.client.registration.google.clientId=googleClientId, spring.security.oauth2.client.registration.google.clientSecret=googleClientSecret)
3. Start the service as a normal Spring Boot app.
4. Go to localhost:9000/login
5. You can use the default user: admin, pass: admin to login for testing. Make sure you delete this user after you are done testing 