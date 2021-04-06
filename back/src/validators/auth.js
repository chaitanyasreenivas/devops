const { check, validationResult } = require("express-validator");

exports.validateMandatorySignupFields = [
  check("firstName").notEmpty().withMessage("firstName is required"),
  check("lastName").notEmpty().withMessage("lastName is required"),
  check("lastName"),
  check("email").isEmail().withMessage("Valid Email is required"),
  check("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 character long")
    .matches(/\d/)
    .withMessage("Password must contain a number"),
];

exports.validateMandatorySigninFields = [
  check("email").isEmail().withMessage("Valid Email is required"),
  check("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 character long"),
];

exports.passwordResetValidator = [
  // check for password
  check("newPassword")
    .notEmpty()
    .withMessage("Required password for reset")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 chars long"),
];
exports.areFieldsValidated = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.array().length > 0) {
    return res.status(400).json({ error: errors.array()[0].msg });
  }
  next();
};
