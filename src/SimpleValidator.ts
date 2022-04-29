export interface SimpleValidationRule<T> {
  validate: (objToValidate: T) => boolean;
  invalidMessage: string;
}

export interface SimpleValidationResult {
  isValid: boolean;
  validationMessage?: string;
}

export function validateRules<T>(
  value: T,
  rules: SimpleValidationRule<T>[]
): SimpleValidationResult {
  const validationResult: SimpleValidationResult = {
    isValid: true,
  };

  for (const rule of rules) {
    if (!rule.validate(value)) {
      validationResult.isValid = false;
      validationResult.validationMessage = rule.invalidMessage;
      break;
    }
  }

  return validationResult;
}
