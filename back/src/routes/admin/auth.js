const express = require('express');
const { signup, signin, signout } = require('../../controller/admin/auth');
const { validateMandatorySignupFields, areFieldsValidated, validateMandatorySigninFields } = require('../../validators/auth');
const { requireSignin } = require('../../middlewares');
const router = express.Router();

//Admin Authentication from admin Controller
router.post('/admin/signup', validateMandatorySignupFields, areFieldsValidated, signup);
router.post('/admin/signin', validateMandatorySigninFields, areFieldsValidated , signin);
router.post('/admin/signout', signout)


module.exports = router;