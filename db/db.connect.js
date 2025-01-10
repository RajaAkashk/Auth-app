const mongoose = require("mongoose");
require("dotenv").config();

const mongoKey = process.env.MONGODB;

const initializeDatabase = async () => {
  await mongoose
    .connect(mongoKey)
    .then(() => console.log("Connected Successfully."))
    .catch((error) => console.log("Error in connecting: ", error));
};

module.exports = { initializeDatabase };
