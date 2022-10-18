const Mongoose = require( 'mongoose');
const ProductModel = new Mongoose.Schema(
    {
        productName:{
            type: String,
            required:true
        }, 
        price:{
            type: Number,
            required:true
        },
        productImageUrl:{
            type:String
        },
        size:{
            type:String
        },
        isDeleted:{
            type: Boolean
        }
    },{timestamps:true}
);

module.exports = Mongoose.model("ProductSchema",ProductModel);

