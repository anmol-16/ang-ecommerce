const Mongoose = require('mongoose');
const OrderModel = new Mongoose.Schema({
    date:{
        type:Date
    },
    userId:{
        type:{
            type: Mongoose.Schema.Types.ObjectId, 
            ref: 'UserSchema'
        }
    },
    details:{
        type:{
            type:Mongoose.Schema.Types.ObjectId,
            ref:'CartSchema'
        }
    },
    checkout:{
        type:Boolean
    }
})

module.exports = Mongoose.model("OrderSchema",OrderModel);