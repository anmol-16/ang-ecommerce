const express = require('express');
const UserSchema = require('../model/user.model');
const user = express.Router();
const mongoose = require('mongoose')
    //working fine
const addUserDetails = async (req, res, next) => {
    try{
    const {firstName, lastName, email, phoneNumber} = req.body;
    const us = await UserSchema.create({
        firstName,
        lastName,
        email,
        phoneNumber
    });
        console.log("User details successfully saved");
        console.log(us);
        return res.json({
            status: true,
            msg: "User Added",
            user: us
        })
    }
    catch(e) {
        console.log(e);
        console.log("User cant be saved");
        return res.json({
            status:false,
            msg:"cant save the user"
        })
    }
}
    //working fine
const getAllUsers = async (req, res, next) => {
    //admin request
    try{
        const allUser = await UserSchema.find();
        console.log(allUser,"All user details");

        return res.json({
            status:true,
            msg:"here are the details of all users",
            data:allUser
        })
    }catch(e){
        console.log(e);
        return res.json({
            status:true,
            msg:"Can't get all the users"
        })
    }

};
    //working fine
const deleteUser = async (req, res, next) => {
    try{
        await UserSchema.findByIdAndUpdate(req.params.id,{
            isDeleted:true
        })
        return res.json({
            status: true,
            code:"200",
            msg : "User is deleted"
        })
    } catch(e){
        console.log(e);
        console.log("user can not be deleted");
    }
};


    // working fine
const updateUser = async (req, res, next) => {
    const profile_id = req.params.id;
    console.log(profile_id, "Here is the profile id");
    const {email, firstName, lastName, password, phoneNumber} = req.body;
    try{
        const currentUser = await UserSchema.findByIdAndUpdate(profile_id,{
            email,
            firstName,
            lastName,
            password,
            phoneNumber
        })
        console.log(currentUser);
        return res.json({
            status: true,
            code:"200",
            msg:"User updated Successfully"
        })
    } catch(e){
        console.log(e);
        console.log("User can't be updated");
        return res.json({
            status: true,
            code:"201",
            msg:"user details can't updated"
        })
    }
}
//working fine
const getUserDetailsbyId = async (req, res, next) =>{
    try{
        const userId = req.query.userId ? req.query.userId : req.id;

        const user = await UserSchema.findById(userId);

        return res
        .status(200)
        .json({
            status:true,
            code:"200",
            data:user
        })                               
    }catch(e){
        console.log(e);
        return res.json({
            status:false,
            msg:"can't get user details"
        })
    }
}


module.exports = {
    getUserDetailsbyId,
    updateUser,
    deleteUser,
    getAllUsers,
    addUserDetails
}