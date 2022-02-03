import express from 'express'
import jwt from 'jsonwebtoken'

import User from '../models/User'
import parseErrors from '../utils/parseErrors'
import { sendConfirmationEmail, sendResetPasswordEmail } from '../mailer'

const router = express.Router()

router.post('/', (req, res) => {
  const { email, password } = req.body.user
  const user = new User({ email })
  user.setPassword(password)
  user.setConfirmationToken()
  user
    .save()
    .then(userRecord => {
      sendConfirmationEmail(userRecord)
      res.json({ user: userRecord.toAuthJSON() })
    })
    .catch(err => res.status(400).json({ errors: parseErrors(err.errors) }))
})

router.post('/confirmation', (req, res) => {
  const { token } = req.body
  User.findOneAndUpdate(
    { confirmationToken: token },
    { confirmationToken: '', isConfirmed: true },
    { new: true },
  ).then(
    user =>
      user
        ? res.json({ user: user.toAuthJSON() })
        : res.status(400).json({ error: 'Failed authorisation' }),
  )
})

router.post('/reset_password_request', (req, res) => {
  const { email } = req.body
  User.findOne({ email }).then(user => {
    if (user) {
      sendResetPasswordEmail(user)
      res.json(`Email has been sent to: ${user.email}`)
    } else {
      res
        .status(400)
        .json({ errors: { global: 'There is no user with such email' }, user })
    }
  })
})

router.post('/validate_token', (req, res) => {
  const { token } = req.body
  jwt.verify(token, process.env.JWT_SECRET, err => {
    if (err) {
      res.status(401).json('err')
    } else {
      res.json('fine')
    }
  })
})

router.post('/reset_password', (req, res) => {
  const { password, token } = req.body.data
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      res.status(401).json({ errors: { global: 'Invalid token' } })
    } else {
      User.findOne({ _id: decoded._id }).then(user => {
        if (user) {
          user.setPassword(password)
          user.save().then(() => res.json('new password saved'))
        } else {
          res.status(404).json({ errors: { global: 'Password not saved' } })
        }
      })
    }
  })
})

export default router
