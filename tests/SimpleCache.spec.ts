import SimpleCache from "../src/SimpleCache";
import { SimpleValidationRule, validateRules } from "../src/SimpleValidator";

describe("After setItem", () => {
  const simpleCache = new SimpleCache<string>();

  simpleCache.setItem("X", "value");

  it("should retrieve with getItem key", async () => {
    expect(simpleCache.getItem("X")).toEqual("value");
  });
  it("should not retrieve with getItem and different key", async () => {
    expect(simpleCache.getItem("Y")).toBeUndefined();
  });
});
