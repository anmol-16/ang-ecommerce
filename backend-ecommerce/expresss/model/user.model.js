
   const Mongoose = require('mongoose')
   const validator = require('validator')
   const bcrypt = require('bcryptjs')
   const jwt = require('jsonwebtoken')

   const UserModel = new Mongoose.Schema({
      firstName: {
         type: String,
         required: true
      },
      lastName: {
         type: String,
         required: true
      },
      phoneNumber:{
         type:String,
      },
      email: {
         type: String,
         unique: true,
         lowercase: true,
         validate: value => {
            if (!validator.isEmail(value)) {
                  throw new Error({error: 'Invalid Email address'})
            }
         }
      },
      password: {
         type: String,
         required: true,
         minLength: 7
      },
      tokens: [{
         token: {
            type: String,
            required: true
         }
      }]
   })

   UserModel.pre('save', async function (next) {
      const user = this
      if (user.isModified('password')) {
         user.password = await bcrypt.hash(user.password, 8)
      }
      next()
   })

   UserModel.methods.generateAuthToken = async function() {
      const user = this
      const token = jwt.sign({_id: user._id}, process.env.JWT_KEY)
      user.tokens = user.tokens.concat({token})
      await user.save()
      return token
   }

   UserModel.statics.findByCredentials = async (email, password) => {
      const user = await UserModel.findOne({ email} )
      if (!user) {
         throw new Error({ error: 'Invalid login credentials' })
      }
      const isPasswordMatch = await bcrypt.compare(password, user.password)
      if (!isPasswordMatch) {
         throw new Error({ error: 'Invalid login credentials' })
      }
      return user
   }

   module.exports = Mongoose.model("UserSchema",UserModel);
