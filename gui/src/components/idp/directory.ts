import type { IdpEnvironmentInfo, IdpIdentityInfo } from "../../lib/idp";

/** The identity and environment lists every tab reads, loaded once by the page. */
export interface IdpDirectory {
  identities: { entity_id: string; info: IdpIdentityInfo }[];
  environments: { name: string; info: IdpEnvironmentInfo }[];
  /** Names of the environments that are not retired. */
  activeEnvironments: string[];
  reload: () => Promise<void>;
}
