# CSC templates

When `getconfig.esp` returns a `portal-csc-auth-cookie`, `gp_recon.py`
extracts the criteria, generates `required_csc.xml` here, and stops. Full raw
responses are saved only with `--raw-save`.

Review the generated XML, replace every device-specific placeholder, then
rerun with `--csc-template csc_templates/required_csc.xml --host-id ID
--serial SERIAL`. Existing templates are never overwritten; later copies have
a timestamp (and a numeric suffix if necessary).

Every template must contain these placeholders:

- `{{PORTAL_CSC_AUTH_COOKIE}}`
- `{{USERNAME}}`
- `{{CLIENT_OS}}`
- `{{HOST_ID}}`
- `{{DEVICE_SERIAL_NUMBER}}`
- `{{CSC_DIGEST}}`

The script XML-escapes substituted values, calculates the CSC digest, saves
the rendered report under `gp_recon_output/generated/csc-report.xml`, and then sends it to
`getconfig_csc.esp`.

Additional placeholders can be supplied with repeated `--csc-var NAME=VALUE`
arguments.
