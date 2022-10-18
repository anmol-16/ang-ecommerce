const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const userRoutes = require('../expresss/routes/user.routes');
const cartRoutes = require('../expresss/routes/cart.route');
const productRoutes = require('../expresss/routes/product.route');
const orderRoutes = require('../expresss/routes/order.route');
const app = express();
const mongoose = require('mongoose');
const { urlencoded } = require('body-parser');
const db_link = "mongodb+srv://lexev:ChL30jWRxE3iJGnK@cluster0.v7vjoz9.mongodb.net/test"
mongoose.connect(db_link,{useNewUrlParser:true}).then(
    ()=>{
        console.log("Database is connected");
    },

    (err) =>{
        console.log("can't connect to the database" +err);
    }
)
app.use(cors());
app.use(bodyParser.urlencoded({extended: false}));
app.use(express.json()); // converts data collected from frontend to json obj


// app.use('/',(req, res, next) =>{
//     res.status(404).send('Page not Found')
// })
//user checkout controller 
// rename all the folder of contrtoller to services
//

app.use('/api',userRoutes);
app.use('/api',cartRoutes);
app.use('/admin',productRoutes);
app.use('/api/user',orderRoutes);

app.listen(3333, ()=>{
    console.log("Server is set up on the server");
});


