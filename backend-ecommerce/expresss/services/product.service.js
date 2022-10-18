const express = require('express');
const ProductSchema = require('../model/product.model');
const mongoose = require('mongoose');


    //working fine
const addProduct = async (req, res, next) => {
    try{
        const {productName, price, productImageUrl, size} =req.body;
        const product = await ProductSchema.create({
            productName,
            price,
            productImageUrl,
            size
         });
        console.log("product details succesfully saved");
        return res.json({
            status:true,
            msg:"successfully product saved",
            data: product
        })
    }catch(e){
        console.log(e);
        return res.json({
            status:false,
            msg:"not saved"
        })
    }
};
    //working fine
const updateProduct = async (req, res, next) => {
    const product_id = req.params._id;
    console.log(product_id, "Here is the product id");
    const {productName, price, productImageUrl, size} = req.body;
    try{
        const currentProduct = await ProductSchema.findByIdAndUpdate(product_id,{
            productName, 
            price, 
            productImageUrl,
            size
        })
        console.log(currentProduct);
        return res.json({
            status: true,
            code:"200",
            msg:"Product updated Successfully",
            currentProduct
        })
    } catch(e){
        console.log(e);
        console.log("product can't be updated");
        return res.json({
            status: true,
            code:"201",
            msg:"product details can't updated"
        })
    }
};
    //working fine
const deleteProduct = async (req, res, next) => {
    try{
        await ProductSchema.findByIdAndUpdate(req.params._id,{
            isDeleted:true
        })
        return res.json({
            status: true,
            code:"200",
            msg : "Product is deleted"
        })
    } catch(e){
        console.log(e);
        console.log("Product can not be deleted");
    }
};
    //working fine
const getProduct = async (req, res, next) => {
    try{    
        const productInfo = await ProductSchema.find();

        console.log(productInfo);

        return res.json({
            status:true,
            msg:"details of the products",
            data:productInfo
        })

    }catch(e){
        console.log(e);
        return res.json({
            status:false,
            msg:"error occured!",
        })
    }
};
    //working fine
const getOneProduct = async (req, res, next) => {
    try{    
        const productInfo = await ProductSchema.find();

        console.log(productInfo);

        return res.json({
            status:true,
            msg:"details of the products",
            data:productInfo
        })

    }catch(e){
        console.log(e);
        return res.json({
            status:false,
            msg:"error occured!",
        })
    }
};


module.exports = {
    addProduct,
    updateProduct,
    deleteProduct,
    getProduct,
    getOneProduct
}