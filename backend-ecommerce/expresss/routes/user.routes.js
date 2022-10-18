const express = require('express');

const {
    getUserDetailsbyId,
    updateUser,
    deleteUser,
    getAllUsers,
    addUserDetails
} = require('../services/user.service');

const userRouter = express.Router();

userRouter
    .post('/add-user',addUserDetails)
    .get('/get-user/:id',getUserDetailsbyId)
    .get('/get-all-user',getAllUsers)
    .put('/update-user/:id',updateUser)
    .delete('/delete-user/:id',deleteUser)

module.exports = userRouter;