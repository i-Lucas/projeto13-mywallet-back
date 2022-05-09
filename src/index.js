import express from "express";
import mongodb from "mongodb";
import dotenv from "dotenv";
import cors from "cors";
import joi from "joi";
import { v4 as uuid } from "uuid";
import bcrypt from "bcrypt";
import dayjs from "dayjs";

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
    const schema = joi.object({ email: joi.string().required(), password: joi.string().required() });

    const validate = schema.validate(data);
    if (validate.error) return res.status(422).send(validate.error.details[0].message);

    try {

        const user = await db.collection("users").findOne({ email: data.email });
        const username = user.username;

        if (user && bcrypt.compareSync(req.body.password, user.password)) {

            const token = uuid();
            const time = new Date().toLocaleTimeString();
            const userID = user._id;

            await db.collection("sessions").insertOne({ time, token, userID });
            return res.status(200).send({ username, token });

        } else return res.status(404).send("invalid email or password");

    } catch (error) { return res.status(500).send("error while accessing database"); }

});

app.post("/sign-up", async (req, res) => {

    const { username, password, email, repeat_password } = req.body;

    const schema = joi.object({

        username: joi.string().alphanum().min(3).max(10).required(),
        email: joi.string().email().required(),
        password: joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')),
        repeat_password: joi.ref('password')
    });

    const validate = schema.validate({ username, password, email, repeat_password });
    if (validate.error) return res.status(422).send(validate.error.details[0].message);

    try {

        const user = await db.collection("users").findOne({ email: email });
        if (user) return res.status(409).send("this email already exists");

        await db.collection("users").insertOne({ username, email, password: bcrypt.hashSync(password, 10) });
        res.sendStatus(201);

    } catch (error) { return res.status(500).send("error while accessing database"); }

});

app.post("/historic", async (req, res) => {

    const { authorization } = req.headers;
    const token = authorization?.replace('Bearer ', '');

    const data = req.body;
    const schema = joi.object({

        amount: joi.number().required(),
        description: joi.string().min(5).required(),
        type: joi.string().required()
    });

    const validate = schema.validate(data);
    if (validate.error) return res.status(422).send(validate.error.details[0].message);

    try {

        const session = await db.collection("sessions").findOne({ token });
        if (!session) return res.status(403).send("session expired");

        const user = await db.collection("users").findOne({ _id: session.userID });
        if (!user) return res.status(403).send("you must be logged in to continue");

        await db.collection("historic").insertOne({

            userID: user._id,
            time: `${dayjs().date()}/${dayjs().month() + 1}`,
            type: data.type,
            amount: data.amount,
            description: data.description
        });

        res.sendStatus(201);

    } catch (error) { return res.status(500).send("error while accessing database"); }

});

app.get("/historic", async (req, res) => {

    const { authorization } = req.headers;
    const token = authorization?.replace('Bearer ', '');

    try {

        const session = await db.collection("sessions").findOne({ token });
        if (!session) return res.status(403).send("session expired");

        const user = await db.collection("users").findOne({ _id: session.userID });
        if (!user) return res.status(403).send("you must be logged in to continue");

        const historic = await db.collection("historic").find({ userID: user._id }).toArray();
        return res.send(historic);

    } catch (error) { return res.status(500).send("error while accessing database"); }

});