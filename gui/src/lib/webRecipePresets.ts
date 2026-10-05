//! Vendor starting points for a `form` web login recipe
//! (features/web-application-connect.md §2, Phase 2).
//!
//! **Every preset here is UNVERIFIED against a live appliance.** They were
//! written from each vendor's publicly documented or widely known login form
//! (field names and ids that browser-automation scripts and vendor docs
//! reference), without recording a real login page. Selectors drift between
//! firmware and product versions, and the success / failure conditions are the
//! least certain part of each one. A preset is a starting point: apply it,
//! press "Test recipe" against the real appliance, and adjust. The UI says so
//! on the picker and on every applied preset, and `unverified` is a literal
//! `true` so no entry can be added as "verified" by accident; flip it only with
//! a recorded login page behind the change.
//!
//! A preset is a function of the profile's origin: a recipe's URLs must sit on
//! the profile's origin set (§2), so the origin is filled in when it is
//! applied. Every preset is held to {@link validateWebRecipe} and
//! {@link checkRecipeOrigins} in `src/test/webRecipe.test.ts`.

import type { WebLoginRecipe } from "./types";

export interface WebRecipePreset {
  /** Stable id; the vendor id of the `web_application.vendor` enum. */
  id: "fortigate" | "vcenter" | "idrac" | "ilo" | "pfsense" | "grafana" | "jenkins";
  label: string;
  /** Short operator-facing note: what it assumes and what to check. */
  note: string;
  /** Always `true`: see the module comment. */
  readonly unverified: true;
  /** The recipe for a login page at `origin` (`scheme://host[:port]`, as the
   *  server's `origin_key` writes it). */
  build: (origin: string) => WebLoginRecipe;
}

const UNVERIFIED_SUFFIX = " (unverified against a live appliance)";

export const WEB_RECIPE_PRESETS: readonly WebRecipePreset[] = [
  {
    id: "fortigate",
    label: "FortiGate (FortiOS)",
    note:
      "FortiOS 6/7 admin login at /login: username and secretkey fields, a login button, then the " +
      "/ng/ console. For token 2FA, add a step that fills the token field with the TOTP value.",
    unverified: true,
    build: (o) => ({
      version: 1,
      vendor: "fortigate",
      steps: [
        {
          when_url: `${o}/login*`,
          actions: [
            { fill: "input[name=username]", value: "username" },
            { fill: "input[name=secretkey]", value: "password" },
            { click: "button#login_button" },
          ],
        },
      ],
      success_when: { url: `${o}/ng/*` },
      failure_when: { selector: "#login_error, .error-message" },
      timeout_secs: 30,
    }),
  },
  {
    id: "vcenter",
    label: "VMware vCenter (vSphere Client)",
    note:
      "vSphere Client 7/8 redirects /ui to the SSO form under /websso/SAML2/SSO/. Use the vCenter " +
      "address as the start URL; the console lives under /ui/. Single-sign-on realms other than " +
      "vsphere.local use the same form.",
    unverified: true,
    build: (o) => ({
      version: 1,
      vendor: "vcenter",
      steps: [
        {
          when_url: `${o}/websso/SAML2/SSO/*`,
          actions: [
            { fill: "input#username", value: "username" },
            { fill: "input#password", value: "password" },
            { click: "input#submit" },
          ],
        },
      ],
      success_when: { url: `${o}/ui/*` },
      failure_when: { selector: ".error, #error" },
      timeout_secs: 30,
    }),
  },
  {
    id: "idrac",
    label: "Dell iDRAC",
    note:
      "iDRAC 8/9 login at /login.html: user and password fields and the Log In button, then the " +
      "console under /restgui/. iDRAC 9 firmware changes its markup between releases; check the " +
      "selectors after an upgrade.",
    unverified: true,
    build: (o) => ({
      version: 1,
      vendor: "idrac",
      steps: [
        {
          when_url: `${o}/login.html*`,
          actions: [
            { fill: "input#user", value: "username" },
            { fill: "input#password", value: "password" },
            { click: "#btnOK" },
          ],
        },
      ],
      success_when: { url: `${o}/restgui/*` },
      failure_when: { selector: "#errorMsg, .error-message" },
      timeout_secs: 30,
    }),
  },
  {
    id: "ilo",
    label: "HPE iLO",
    note:
      "iLO 4/5 login page: username and password fields and the login button. The console is a " +
      "single-page app on the same URL, so success is judged by an element of the signed-in shell. " +
      "That selector is the least certain part; adjust it from the test report.",
    unverified: true,
    build: (o) => ({
      version: 1,
      vendor: "ilo",
      steps: [
        {
          when_url: `${o}/*`,
          actions: [
            { fill: "input#username", value: "username" },
            { fill: "input#password", value: "password" },
            { click: "#login-form__submit" },
          ],
        },
      ],
      success_when: { selector: "#masthead, #appFrame" },
      failure_when: { selector: "#loginErrorMessage, .login-error" },
      timeout_secs: 40,
    }),
  },
  {
    id: "pfsense",
    label: "pfSense",
    note:
      "pfSense 2.x login at /index.php: usernamefld and passwordfld fields and the Sign In button. " +
      "The dashboard is at the same URL, so success is judged by the Logout link in the signed-in " +
      "navigation bar.",
    unverified: true,
    build: (o) => ({
      version: 1,
      vendor: "pfsense",
      steps: [
        {
          when_url: `${o}/index.php*`,
          actions: [
            { fill: "input[name=usernamefld]", value: "username" },
            { fill: "input[name=passwordfld]", value: "password" },
            { click: "input[name=login]" },
          ],
        },
      ],
      success_when: { selector: 'a[href*="logout"]' },
      failure_when: { selector: ".alert-danger, .text-danger" },
      timeout_secs: 30,
    }),
  },
  {
    id: "grafana",
    label: "Grafana",
    note:
      "Grafana 9/10 login at /login: user and password fields and the submit button. Success is " +
      "judged by the signed-in navigation menu, whose selector Grafana changes between releases; " +
      "adjust it from the test report. Instances behind an SSO provider need that provider's " +
      "origin in the allowed origins and a different recipe.",
    unverified: true,
    build: (o) => ({
      version: 1,
      vendor: "grafana",
      steps: [
        {
          when_url: `${o}/login*`,
          actions: [
            { fill: "input[name=user]", value: "username" },
            { fill: "input[name=password]", value: "password" },
            { click: "button[type=submit]" },
          ],
        },
      ],
      success_when: { selector: 'nav[aria-label="Main menu"], [data-testid="data-testid Nav menu"]' },
      failure_when: { selector: '[role="alert"]' },
      timeout_secs: 30,
    }),
  },
  {
    id: "jenkins",
    label: "Jenkins",
    note:
      "Jenkins built-in security realm at /login: j_username and j_password fields posted to " +
      "j_spring_security_check. A wrong password redirects to /loginError, which is what failure " +
      "keys on; success is the Log out link in the page header.",
    unverified: true,
    build: (o) => ({
      version: 1,
      vendor: "jenkins",
      steps: [
        {
          when_url: `${o}/login*`,
          actions: [
            { fill: "input[name=j_username]", value: "username" },
            { fill: "input[name=j_password]", value: "password" },
            { submit: "form[action=j_spring_security_check]" },
          ],
        },
      ],
      success_when: { selector: 'a[href$="/logout"]' },
      failure_when: { url: `${o}/loginError*` },
      timeout_secs: 30,
    }),
  },
];

/** The picker label: always carries the caveat. */
export function presetLabel(preset: WebRecipePreset): string {
  return `${preset.label}${UNVERIFIED_SUFFIX}`;
}

export function findPreset(id: string): WebRecipePreset | undefined {
  return WEB_RECIPE_PRESETS.find((p) => p.id === id);
}
