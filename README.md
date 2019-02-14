# Wallaby

Wallaby is a simple operator to generate a default jumpage for your kubernetes cluster based on the ingresses configured on your system.

The resulting page is template based an can be fully customized.

## Feaures

-   Watches all ingresses and
-   Template based index-page
-   Serve static content
-   OIDC Authentication build in
-   Retreive information from HELM
-   try to guess an icon if none is specified
-   custom annotations for customziations
-   optional sentry integration

# Installation

## Standalone via Helm Chart

## Default Backend for NGINX Ingress

The stable NGINX chart does not allow to specify a service account for the default backend. Thus we have to deploy it sepearatly.

1. Deploy Via Helm Chart
2. Reconfigure Helm Deployment for nginx
    - disable default backend
    - set controller.extraArgs to - --default-backend-service=

## Command Line Arguments

## Environment Variables

SENTRY_DSN=<your_dns>

## Annotations

    wallaby.autonubil.net/hidden

    wallaby.autonubil.net/index
    wallaby.autonubil.net/name
    wallaby.autonubil.net/url
    wallaby.autonubil.net/visibility
    wallaby.autonubil.net/description
    wallaby.autonubil.net/icon
    wallaby.autonubil.net/overlay
    wallaby.autonubil.net/tags

    wallaby.autonubil.net/filter

### Filter Syntax

    UP NEXT....

# Roadmap
-  implement filtering based on user claims
-  Add Services too
