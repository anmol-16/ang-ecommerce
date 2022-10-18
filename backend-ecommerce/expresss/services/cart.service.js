    const express = require("express");
    const CartSchema = require("../model/cart.model");
    const mongoose = require("mongoose");
    const OrderSchema = require('../model/order.model')

    //working fine
    const getCartDetails = async (req, res, next) => {
    try {
        const cartInfo = await CartSchema.findById(req.params.id);
        console.log(cartInfo);
        return res.json({  
            status: true,
            msg: "details shown",
            data: cartInfo,
        });
    } catch (e) {
        console.log(e);
        return res.json({
            status: false,
            msg: "error occured",
        });
    }
    };
    //working fine
    const updateCart = async (req, res, next) => {
        const cartId = req.params.id;
        console.log(cartId);
    try {
        const list =req.body.list;
        const userId = req.body.userId;
        const currentCart = await CartSchema.findByIdAndUpdate(cartId, {
            list,
            userId
        });
        console.log(currentCart);

        return res.json({
            status: true,
            code: 200,
            msg: "Cart Updated successfully",
        });
    } catch (e) {
        console.log(e);
        console.log("Cart can't be updated");
        return res.json({
            status: false,
            code: 201,
            msg: "cart can't be updated successfully",
        });
    }
    };

    const createOrderFromCart = async (req, res, next) => {
        const userId = req.params.id;
        try {
            const cartToOrder = await CartSchema.findById({userId});
            if(cartToOrder){
                const newOrder = await OrderSchema.create({
                    date:FileSystem.date(),
                    userId:userId,
                    details: cartToOrder,
                    checkout:true
                })
                return res.json({
                    status:true,
                    msg:"Order created successfully",
                    data:newOrder
                })
                
            }
            else{
                return res.json({
                    status:false,
                    msg:"No order to eexceute"
                })
            }
        } catch (e) {
            console.log(e);

            return res.json({
                status:false,
                msg:"Can't create order from cart"
            })
        }
    }
    //working fine except when adding to current cart
    const addToCart = async (req, res, next) => {
        const list = req.body.list;
        const userId = req.body.userId;
    try {
        const  cartProduct = await CartSchema.create({
                list,
                userId
                });
            
        console.log("Product added to cart");
        console.log(cartProduct);
        
        return res.json({
            status: true,
            msg: "Product Added",
            carts: cartProduct,
        });
    } catch (e) {
        console.log(e);
        console.log("cart cant be saved");
        return res.json({
            status: false,
            msg: "cant save the product",
        });
    }
    };

    //working fine
    const emptyCart = async (req, res, next) => {
        const cartId = req.params.id;

        try{
            const list =[];
            const cartProduct = await CartSchema.findByIdAndUpdate(cartId,{
                list:list
            })
            console.log(cartProduct);

            return res.json({
                status:true,
                msg:"cart empty sucessfully",
                cart:cartProduct
            })
        }catch(e){
            console.log(e);

            return res.json({
                status:true,
                msg:"cart can't be emptied successfully"
            })
        }
    }

    module.exports = {
    getCartDetails,
    addToCart,
    updateCart,
    emptyCart,
    createOrderFromCart
    };
