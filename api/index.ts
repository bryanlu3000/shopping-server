import { MongoClient, ObjectId } from "mongodb";
import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import jwt, { JwtPayload, Secret } from "jsonwebtoken";
dotenv.config();

interface CustomRequest extends Request {
  email: string;
}

interface TokenPayload extends JwtPayload {
  email: string;
}

const uri = process.env.CONNECTIONSTRING!;
const client = new MongoClient(uri);

const dbShop = client.db("shoe-shopping");
const itemsCollection = dbShop.collection("items");
const categoriesCollection = dbShop.collection("shoesCategories");

const dbUser = client.db("sign-in-demo");
const usersCollection = dbUser.collection("users");

// To run a text search query, need to create a text index on the field to query.
// itemsCollection.createIndex({ name: "text" });
// Here we use regex instead to query on name field.

const app = express();
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));

//////////////////////////////////////////////////////////////////////////////
// CORS setting
const allowedOrigins = [
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "https://shopping-frontend-gilt.vercel.app/*",
];

const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    if (allowedOrigins.indexOf(origin!) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  optionsSuccessStatus: 200,
};

const credentials = (req: Request, res: Response, next: NextFunction) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin!)) {
    res.header("Access-Control-Allow-Credentials", "true");
  }
  next();
};

app.use(credentials); // Must before CORS! Handle options credentials check and fetch cookies credentials requirement.
app.use(cors(corsOptions)); // Cross Origin Resource Sharing
app.use(express.urlencoded({ extended: false })); // Use body parser for POST and PUT request
app.use(express.json()); //Enable to parse JSON in req.body
app.use(cookieParser()); // Middleware for cookies

//////////////////////////////////////////////////////////////////////////////
// Middleware to verify JWT accessToken
const verifyJWT = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.sendStatus(401);
  }
  const token = authHeader.split(" ")[1];

  jwt.verify(
    token,
    process.env.ACCESS_TOKEN_SECRET as Secret,
    (err, decoded) => {
      if (err) {
        return res.status(403).send("accessToken verification failed!!!"); // invalid accessToken
      }

      (req as CustomRequest).email = (decoded as TokenPayload).email;
      next();
    }
  );
};

//////////////////////////////////////////////////////////////////////////////
// Refresh JWT accessToken
app.get("/api/refresh", async (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) {
    return res.status(401).send("No refreshToken found!!!");
  }
  const refreshToken = cookies.jwt;

  try {
    // search the refreshToken
    const resultFind = await usersCollection.findOne({
      refreshToken,
    });
    if (!resultFind) {
      return res
        .status(403)
        .send("refreshToken is not found in the backend database!!!"); // Forbidden
    }

    // evaluate jwt refreshToken
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET as Secret,
      (err: any, decoded: any) => {
        if (err || resultFind.email !== decoded.email) {
          return res.status(403).send("refreshToken verification failed!!!");
        }
        const accessToken = jwt.sign(
          { email: resultFind.email },
          process.env.ACCESS_TOKEN_SECRET as Secret,
          { expiresIn: "300s" }
        );
        return res.json({ accessToken });
      }
    );
  } catch (error: any) {
    return res.status(500).json({ message: error.message });
  }
});

//////////////////////////////////////////////////////////////////////////////
// user sign in
app.post("/api/signin", async (req: Request, res: Response) => {
  const { email, password } = req.body;

  // check if the email and password are empty
  if (!email || !password) {
    return res
      .status(400)
      .json({ message: "Email and password are required." });
  }

  try {
    // search the email
    const resultFind = await usersCollection.findOne({
      email,
    });

    if (!resultFind) {
      return res.sendStatus(401); // Unauthorized, email not found
    }

    // evaluate password
    const match = await bcrypt.compare(password, resultFind.password);
    if (match) {
      // create JWTs
      const accessToken = jwt.sign(
        { email: resultFind.email },
        process.env.ACCESS_TOKEN_SECRET as Secret,
        { expiresIn: "300s" }
      );

      const refreshToken = jwt.sign(
        { email: resultFind.email },
        process.env.REFRESH_TOKEN_SECRET!,
        { expiresIn: "1d" }
      );

      // Saving refreshToken with current user
      const resultRefreshToken = await usersCollection.updateOne(
        { email: { $eq: resultFind.email } },
        { $set: { refreshToken } }
      );

      if (resultRefreshToken.acknowledged) {
        res.cookie("jwt", refreshToken, {
          httpOnly: true,
          sameSite: "none",
          secure: true,
          maxAge: 24 * 60 * 60 * 1000,
        });

        return res
          .status(201)
          .json({ accessToken, message: `Login Success ===> ${email}` });
      } else {
        return res.json("Errors! Try again later.");
      }
    } else {
      return res.sendStatus(401); // Unauthorized, password not match
    }
  } catch (err: any) {
    return res.status(500).json({ message: err.message });
  }
});

//////////////////////////////////////////////////////////////////////////////
// user sign up
app.post("/api/signup", async (req, res) => {
  const { email, password } = req.body;

  // check if the email and password are empty
  if (!email || !password) {
    return res
      .status(400)
      .json({ message: "Email and password are required." });
  }

  try {
    // check for duplicate emails in the db
    const resultFind = await usersCollection.findOne({
      email,
    });
    if (resultFind) {
      return res.status(409).json({
        message: "The email has already existed, please change to another one.",
      });
    }

    // encrypt the password, salt is 10
    const hashedPwd = await bcrypt.hash(password, 10);

    // insert a new email and password.
    const result = await usersCollection.insertOne({
      email,
      password: hashedPwd,
    });

    if (result.acknowledged) {
      return res
        .status(201)
        .json({ message: `Register Success ===> ${email}` });
    } else {
      return res.json("Errors! Try again later.");
    }
  } catch (err: any) {
    return res.status(500).json({ message: err.message });
  }
});

//////////////////////////////////////////////////////////////////////////////
// Logout and Delete JWT refreshToken
app.get("/api/signout", async (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) {
    return res.sendStatus(406); // Not Acceptable
  }
  const refreshToken = cookies.jwt;

  try {
    // search the refreshToken
    const resultFind = await usersCollection.findOne({
      refreshToken,
    });
    if (!resultFind) {
      res.clearCookie("jwt", {
        httpOnly: true,
        sameSite: "none",
        secure: true,
      });
      return res.sendStatus(202); // Accepted
    }

    // Delete refreshToken with current user
    const resultDeleteToken = await usersCollection.updateOne(
      { refreshToken: { $eq: resultFind.refreshToken } },
      { $set: { refreshToken: "" } }
    );
    if (resultDeleteToken.acknowledged) {
      res.clearCookie("jwt", {
        httpOnly: true,
        sameSite: "none",
        secure: true,
      });
      return res.sendStatus(204); // No Content
    }
  } catch (err: any) {
    return res.status(500).json({ message: err.message });
  }
});

//////////////////////////////////////////////////////////////////////////////
// Get store items
// req.query: {limit, page, category, nameQuery}
app.get("/api/items", async (req, res) => {
  interface Query {
    category: string;
    name: {
      $regex: string;
    };
  }

  try {
    // await client.connect();

    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 8;
    const { category, nameQuery } = req.query;

    const query: Query = {} as Query;

    // If category exists in the query from the frontend and is not 'all'
    if (category && category !== "all") {
      query.category = category as string;
    }

    // If nameQuery exists in the query from the frontend and is not empty
    if (nameQuery && nameQuery !== "") {
      query.name = { $regex: nameQuery as string };
    }

    const result = await itemsCollection
      .find(query)
      .sort({ name: 1 }) // sort name in ascending order
      .skip((page - 1) * limit)
      .limit(limit)
      .toArray();

    const itemsCount = await itemsCollection.countDocuments(query);

    return res.status(200).json({ itemsCount, result });
  } catch (err) {
    console.error(err);
    return res.json("Errors! Try again later.");
  }
  // finally {
  //   await client.close();
  // }
});

//////////////////////////////////////////////////////////////////////////////
// Get featured items
// There are only 3-4 featured items in database, no need to add pagination.
app.get("/api/items/featured", async (req, res) => {
  try {
    const result = await itemsCollection
      .find({ featured: true })
      .sort({ name: 1 })
      .toArray();
    return res.status(200).json({ result });
  } catch (err) {
    console.error(err);
    return res.json("Errors! Try again later.");
  }
});

//////////////////////////////////////////////////////////////////////////////
// Get categories
app.get("/api/categories", async (req, res) => {
  try {
    const result = await categoriesCollection
      .find({})
      .sort({ name: 1 })
      .toArray();
    return res.status(200).json({ result });
  } catch (err) {
    console.error(err);
    return res.json("Errors! Try again later.");
  }
});

//////////////////////////////////////////////////////////////////////////////
// Update item rating
app.put("/api/items/rating/:id", verifyJWT, async (req, res) => {
  try {
    const result = await itemsCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      {
        $inc: {
          totalRating: req.body.rating,
          reviewCount: 1,
        },
      }
    );

    if (result.acknowledged) {
      return res.sendStatus(200);
    } else {
      return res.json("Errors! Try again later.");
    }
  } catch (err) {
    console.error(err);
    return res.json("Errors! Try again later.");
  }
});

module.exports = app;
