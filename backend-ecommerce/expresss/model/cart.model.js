const Mongoose = require('mongoose');
const CartModel = new Mongoose.Schema({
    list:
        [{
            productId:{type:Mongoose.Schema.Types.ObjectId,ref:'ProductSchema'},
            quantity:{type:Number}
        }],
        userId:{
            type:String
            //{
            //     type: Mongoose.Schema.Types.ObjectId, 
            //     ref: 'UserSchema'
            // }
        }
});

module.exports = Mongoose.model("CartSchema",CartModel);