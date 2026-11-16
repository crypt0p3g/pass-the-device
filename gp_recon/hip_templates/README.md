# HIP report templates

After `getconfig.esp` succeeds, `gp_recon.py` extracts the portal's
`hip-collection` policy and creates `required_hip.xml` here from the requested
category names.

The generated XML is a review artifact: a skeleton HIP report showing which
categories this portal collects. `gp_recon.py` does not fill it in, does not
submit it, and never connects. Existing templates are never overwritten.

The placeholders mark the values a client supplies at connection time:

- `{{MD5}}`
- `{{USERNAME}}`
- `{{DOMAIN}}`
- `{{HOSTNAME}}`
- `{{HOST_ID}}`
- `{{CLIENT_IP}}` and `{{CLIENT_IPV6}}`
- `{{GENERATE_TIME}}`
- `{{OS_VERSION}}`
- `{{APP_VERSION}}`
