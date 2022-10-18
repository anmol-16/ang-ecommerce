const express = require('express');
const OrderSchema = require('../model/order.model');
const order = express.Router();
const mongoose = require('mongoose');

const getOrderDetails = async (req,res,next) => {
    try{
        const orderId = req.params.id;
        console.log(orderId, " here is your order id");

        const info = await OrderSchema.findById(orderId);

        console.log(info);

        return res.json({
            status:true,
            msg:"Info are here"
        })

    }catch(e){
        console.log(e);
        return res.json({
            status:false,
            message:"can't get the orderdetails"
        })
    }
}

const getAllorderDetails = async (req, res, next) => {
    try {
        const orderArray = await OrderSchema.find();

        console.log(orderArray);

        return res.json({
            status:true,
            msg:"total order",
            data:orderArray
        })
    } catch (error) {
            console.log(e);
            return res.json({
                status:false,
                msg:"Can't get all orders"
            })
    }
}

module.exports = {
    getOrderDetails,
    getAllorderDetails
}