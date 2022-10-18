const express = require('express');

const { getOrderDetails,
    getAllorderDetails } = require('../services/order.service');

const orderRouter = express.Router();

orderRouter
    .get('/order-details',getOrderDetails)
    .get('all-order',getAllorderDetails);

module.exports =  orderRouter
