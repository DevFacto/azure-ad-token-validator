import { SimpleValidationRule, validateRules } from "../src/SimpleValidator";

describe("When single rule", () => {
  describe("and not valid", () => {
    const invalidMessage = "value does not match OK";
    const validationRules: SimpleValidationRule<string>[] = [
      {
        validate: (value) => value === "OK",
        invalidMessage: invalidMessage,
      },
    ];

    const result = validateRules("NOPE", validationRules);
    it("should set isValid to false", async () => {
      expect(result.isValid).toBeFalsy();
    });
    it("should have invalidMessage in result", async () => {
      expect(result.validationMessage).toEqual(invalidMessage);
    });
  });

  describe("and valid value", () => {
    const invalidMessage = "value does not match OK";
    const validationRules: SimpleValidationRule<string>[] = [
      {
        validate: (value) => value === "OK",
        invalidMessage: invalidMessage,
      },
    ];

    const result = validateRules("OK", validationRules);
    it("should set isValid to true", async () => {
      expect(result.isValid).toBe(true);
    });
    it("should not set invalidMessage", async () => {
      expect(result.validationMessage).toBeUndefined();
    });
  });
});

describe("When multiple rules", () => {
  describe("and value does not match any rule", () => {
    const validationRules: SimpleValidationRule<string>[] = [
      {
        validate: (value) => value.length > 3,
        invalidMessage: "too short",
      },
      {
        validate: (value) => value.startsWith("#"),
        invalidMessage: "does not start with #",
      },
    ];

    const result = validateRules("NO", validationRules);
    it("should set isValid to false", async () => {
      expect(result.isValid).toBeFalsy();
    });
    it("should set invalidMessage to first failed rule", async () => {
      expect(result.validationMessage).toEqual("too short");
    });
  });

  describe("and value matches all rules", () => {
    const validationRules: SimpleValidationRule<string>[] = [
      {
        validate: (value) => value.length > 3,
        invalidMessage: "too short",
      },
      {
        validate: (value) => value.startsWith("#"),
        invalidMessage: "does not start with #",
      },
    ];

    const result = validateRules("#YES", validationRules);
    it("should set isValid to false", async () => {
      expect(result.isValid).toBe(true);
    });
    it("should set invalidMessage to first failed rule", async () => {
      expect(result.validationMessage).toBeUndefined();
    });
  });
});
