const express = require('express');

const {
    getCartDetails,
    addToCart,
    updateCart,
    emptyCart,
    createOrderFromCart
} = require('../services/cart.service');

const cartRouter = express.Router();

cartRouter
    .get('/cart-details/:id',getCartDetails)
    .post('/add-to-cart',addToCart)
    .put('/update-cart/:id',updateCart)
    .delete('/empty-cart/:id',emptyCart)
    .post('cart-to-order/:id',createOrderFromCart);

module.exports =  cartRouter