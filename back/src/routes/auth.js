const express = require('express')
const { signup, signin, signout } = require('../controller/auth')
const {
  validateMandatorySignupFields,
  areFieldsValidated,
  validateMandatorySigninFields,
  passwordResetValidator,
} = require('../validators/auth')
const { forgotPassword, resetPassword } = require('../middlewares')

const router = express.Router()

// User Authentication from Controller
router.post(
  '/signup',
  validateMandatorySignupFields,
  areFieldsValidated,
  signup,
)
router.post(
  '/signin',
  validateMandatorySigninFields,
  areFieldsValidated,
  signin,
)
router.post('/admin/signout', signout)
router.put('/forgot-password', forgotPassword)
router.put(
  '/reset-password',
  passwordResetValidator,
  areFieldsValidated,
  resetPassword,
)

// router.post('/profile', requireSignin, (req, res) => {
//     res.status(200).json({ user: 'profile' })
// });

module.exports = router
