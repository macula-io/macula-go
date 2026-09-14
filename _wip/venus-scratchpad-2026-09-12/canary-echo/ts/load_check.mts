// Local-only check: the SDK and its native addon load, and an identity can be made. No network.
import { Identity } from "@macula-io/ts";
const id = Identity.generate();
id.dispose();
console.log("macula-ts loaded, native addon ok, identity generated and disposed");
