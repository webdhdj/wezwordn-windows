import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { HIBPClient, type HIBPTransport } from "../src/hibp-client.js";

class Box {
  prefixes: string[] = [];
}
class MockTransport implements HIBPTransport {
  constructor(private readonly body: string, private readonly box: Box | null = null) {}
  fetchRange(prefix: string): string {
    this.box?.prefixes.push(prefix);
    return this.body;
  }
}

describe("HIBPClient", () => {
  // Known vector: SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
  it("testSHA1KnownVectorAndSplit", () => {
    const hex = HIBPClient.sha1Hex("password");
    assert.equal(hex, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    const { prefix, suffix } = HIBPClient.splitHash(hex);
    assert.equal(prefix, "5BAA6");
    assert.equal(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    assert.equal(prefix.length, 5);
  });

  it("testPwnedFoundWithKAnonymityOnly", () => {
    const box = new Box();
    // Response contains the known suffix for "password" plus a decoy.
    const body =
      "0018A45C4D1DEF81644B54AB7F969B88D65:2\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\n00C9ED1111B7D1111A1111111111111111111:3";
    const client = new HIBPClient(new MockTransport(body, box));
    assert.equal(client.pwnedCount("password"), 9545824);
    assert.equal(client.isPwned("password"), true);
    // Only the 5-char prefix ever reached the transport (two calls above:
    // pwnedCount + isPwned, hence two identical entries).
    assert.deepEqual(box.prefixes, ["5BAA6", "5BAA6"]);
  });

  it("testNotPwnedReturnsZero", () => {
    const client = new HIBPClient(new MockTransport("0018A45C4D1DEF81644B54AB7F969B88D65:2"));
    assert.equal(client.pwnedCount("password"), 0);
    assert.equal(client.isPwned("password"), false);
  });

  it("testParserRejectsMalformed", () => {
    assert.throws(() => HIBPClient.parseResponse("NOCOUNTLINE"));
    assert.throws(() => HIBPClient.parseResponse("ABC:notanumber"));
    const ok = HIBPClient.parseResponse("ABC123:42\nDEF456:7");
    assert.equal(ok.get("ABC123"), 42);
    assert.equal(ok.get("DEF456"), 7);
  });
});
