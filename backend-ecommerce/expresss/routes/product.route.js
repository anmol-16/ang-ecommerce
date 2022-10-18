const express = require('express');

const {
    addProduct,
    updateProduct,
    deleteProduct,
    getProduct,
    getOneProduct
} = require('../services/product.service');

const productRouter = express.Router();

productRouter
    .post('/add-product',addProduct)
    .get('/all-products',getProduct)
    .get('/get-product',getOneProduct)
    .put('/update-product/:productId',updateProduct)
    .delete('/delete-product/:id',deleteProduct)

module.exports =  productRouter
