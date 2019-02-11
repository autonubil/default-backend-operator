# Wallaby

Wallaby is a simple operator to generate a default jumpage for your kubernetes cluster based on the ingresses configured on your system.

The resulting page is template based an can be fully customized.

## Feaures

-   Watches all ingresses and
-   Template based index
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

    wallaby.autonubuil.net/hidden

    wallaby.autonubuil.net/index
    wallaby.autonubuil.net/name
    wallaby.autonubuil.net/url
    wallaby.autonubuil.net/visibility
    wallaby.autonubuil.net/description
    wallaby.autonubuil.net/icon
    wallaby.autonubuil.net/overlay
    wallaby.autonubuil.net/tags

    wallaby.autonubuil.net/filter

### Filter Syntax

    all claimes are flattend and can be

# Roadmap

-   Add Services too
