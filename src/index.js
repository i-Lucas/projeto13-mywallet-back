import express from "express";
import mongodb from "mongodb";
import dotenv from "dotenv";
import cors from "cors";
import joi from "joi";
import { v4 as uuid } from "uuid";
import bcrypt from "bcrypt";

dotenv.config();
const app = express();
app.use(cors(), express.json());

let db = null;

app.listen(process.env.SERVER_PORT, () => {

    console.log(`Server is running on port ${process.env.SERVER_PORT}`);
    const mongoClient = new mongodb.MongoClient(process.env.MONGO_PORT);

    mongoClient.connect().then(() => {

        db = mongoClient.db(process.env.DATABASE_NAME);
        console.log("Connected to database successfully! Happy hacking !");

    }).catch(error => {

        console.log("Error while connecting to database: ", error);
    })
});

app.post("/sign-in", async (req, res) => {

    const data = req.body;

    const schema = joi.object({
        email: joi.string().required(),
        password: joi.string().required()
    });

    const validate = schema.validate(data);
    if (validate.error) return res.status(422).send(validate.error.details[0].message);

    try {

        const user = await db.collection("users").findOne({ email: data.email });
        if (user && bcrypt.compareSync(req.body.password, user.password)) {

            const token = uuid();
            await db.collection("sessions").insertOne({ time: new Date().toLocaleTimeString(), token, userId: user._id });

            const uName = await db.collection("users").findOne({ email: data.email });
            const username = uName.username;
            return res.status(200).send({ username, token });

        } else return res.status(404).send("invalid email or password");

    } catch (error) { return res.status(500).send("error while accessing database"); }

});

app.post("/sign-up", async (req, res) => {

    const { username, password, email } = req.body;

    const regexUsername = /^[a-zA-Z0-9]{3,10}$/;
    const regexPassword = /^[a-zA-Z0-9]{3,10}$/;
    const regexEmail = /^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;

    const schema = joi.object({

        username: joi.string().pattern(regexUsername).required(),
        password: joi.string().pattern(regexPassword).required(),
        email: joi.string().pattern(regexEmail).required(),
        repeat_password: joi.ref('password')
    });

    const validate = schema.validate({ username, password, email });
    if (validate.error) return res.status(422).send(validate.error.details[0].message);

    try {

        const user = await db.collection("users").findOne({ username: username });
        if (user) return res.status(409).send("this user already exists");

        await db.collection("users").insertOne({ username, email, password: bcrypt.hashSync(password, 10) });
        res.sendStatus(201);

    } catch (error) { return res.status(500).send("error while accessing database"); }

});